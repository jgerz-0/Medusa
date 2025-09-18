export const controllerBaseUrl =
  process.env.CONTROLLER_API_BASE_URL ?? 'http://127.0.0.1:8000';

export const controllerApiKey = process.env.CONTROLLER_API_KEY;

export const controllerJwt = process.env.CONTROLLER_JWT;

export const dashboardUser = process.env.DASHBOARD_BASIC_USER ?? 'api';
export const dashboardPassword =
  process.env.DASHBOARD_BASIC_PASSWORD ?? controllerApiKey ?? '';
