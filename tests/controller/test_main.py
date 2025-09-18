import jwt

from controller.main import PrincipalCredential, Settings, _hash_secret


def api_key_headers(api_key: str) -> dict[str, str]:
    return {"X-API-Key": api_key}


def auth_headers(api_key: str = "test-key") -> dict[str, str]:
    return api_key_headers(api_key)


def jwt_headers(settings: Settings, subject: str) -> dict[str, str]:
    token = jwt.encode({"sub": subject}, settings.jwt_secret, algorithm="HS256")
    return {"Authorization": f"Bearer {token}"}


def test_admin_can_create_list_and_revoke_principals(client):
    test_client, settings, session_factory = client

    create_response = test_client.post(
        "/principals",
        json={
            "subject": "svc-transient",
            "auth_method": "api_key",
            "roles": ["analyst"],
            "description": "Temporary analyst access",
        },
        headers=api_key_headers("test-key"),
    )
    assert create_response.status_code == 201, create_response.text
    payload = create_response.json()
    credential_id = payload["id"]
    issued_secret = payload["secret"]
    assert issued_secret

    with session_factory() as session:
        record = session.get(PrincipalCredential, credential_id)
        assert record is not None
        assert record.key_hash == _hash_secret(issued_secret)
        assert record.roles == ["analyst"]

    usable_response = test_client.get("/scans", headers=api_key_headers(issued_secret))
    assert usable_response.status_code == 200
    assert usable_response.json() == {"data": []}

    list_response = test_client.get("/principals", headers=api_key_headers("test-key"))
    assert list_response.status_code == 200
    principals = list_response.json()["data"]
    assert any(principal["id"] == credential_id for principal in principals)
    assert all("secret" not in principal for principal in principals)

    revoke_response = test_client.post(
        f"/principals/{credential_id}/revoke",
        headers=api_key_headers("test-key"),
    )
    assert revoke_response.status_code == 200
    assert revoke_response.json()["revoked_at"] is not None

    post_revoke = test_client.get("/scans", headers=api_key_headers(issued_secret))
    assert post_revoke.status_code == 401


def test_analyst_cannot_access_admin_principal_endpoints(client):
    test_client, settings, _ = client

    list_response = test_client.get("/principals", headers=api_key_headers("analyst-key"))
    assert list_response.status_code == 403

    create_response = test_client.post(
        "/principals",
        json={
            "subject": "svc-denied",
            "auth_method": "api_key",
            "roles": ["analyst"],
        },
        headers=api_key_headers("analyst-key"),
    )
    assert create_response.status_code == 403


def test_scan_enqueue_requires_explicit_role(client):
    test_client, settings, _ = client

    response = test_client.post(
        "/scan",
        json={
            "target_id": "missing",
            "scanner": "nuclei",
            "parameters": {},
        },
        headers=api_key_headers("analyst-key"),
    )
    assert response.status_code == 403


def test_target_creation_requires_write_role(client):
    test_client, settings, _ = client

    response = test_client.post(
        "/targets",
        json={
            "name": "api",
            "scope": "api.internal.example.com",
            "is_authorized": True,
        },
        headers=api_key_headers("analyst-key"),
    )
    assert response.status_code == 403


def test_jwt_admin_and_analyst_permissions(client):
    test_client, settings, _ = client

    admin_headers = jwt_headers(settings, "jwt-admin")
    analyst_headers = jwt_headers(settings, "jwt-analyst")

    admin_response = test_client.get("/principals", headers=admin_headers)
    assert admin_response.status_code == 200

    analyst_response = test_client.get("/principals", headers=analyst_headers)
    assert analyst_response.status_code == 403
