import { render, screen } from '@testing-library/react';
import {
  assignFindingAction,
  updateStatusAction,
  updateTagsAction,
  createCommentAction,
  createJiraTicketAction,
  createGitHubTicketAction,
  createInitialActionState
} from '@/app/findings/[findingId]/actions';
import { UpdateStatusForm } from '@/app/findings/[findingId]/forms';
import {
  assignFinding,
  updateFindingStatus,
  updateFindingTags,
  createFindingComment,
  createJiraTicket,
  createGitHubTicket,
  ControllerError
} from '@/lib/api';

jest.mock('@/lib/api', () => {
  const actual = jest.requireActual('@/lib/api');
  return {
    ...actual,
    assignFinding: jest.fn(),
    updateFindingStatus: jest.fn(),
    updateFindingTags: jest.fn(),
    createFindingComment: jest.fn(),
    createJiraTicket: jest.fn(),
    createGitHubTicket: jest.fn()
  };
});

jest.mock('next/cache', () => ({
  revalidatePath: jest.fn()
}));

jest.mock('react-dom', () => {
  const actual = jest.requireActual('react-dom');
  return {
    ...actual,
    useFormState: jest.fn(() => [{ status: 'idle', message: null }, jest.fn()]),
    useFormStatus: jest.fn(() => ({ pending: false }))
  };
});

const { revalidatePath } = jest.requireMock('next/cache');
const { useFormState, useFormStatus } = jest.requireMock('react-dom');

describe('finding workflow actions', () => {
  beforeEach(() => {
    jest.resetAllMocks();
    (useFormState as jest.Mock).mockReturnValue([
      { status: 'idle', message: null },
      jest.fn()
    ]);
    (useFormStatus as jest.Mock).mockReturnValue({ pending: false });
  });

  it('updates assignment and revalidates the listing on success', async () => {
    (assignFinding as jest.Mock).mockResolvedValue({});

    const formData = new FormData();
    formData.set('findingId', 'finding-7');
    formData.set('assignee', 'analyst@example.com');

    const result = await assignFindingAction(createInitialActionState(), formData);

    expect(assignFinding).toHaveBeenCalledWith('finding-7', 'analyst@example.com');
    expect(result.status).toBe('success');
    expect(result.message).toBe('Assignment updated.');
    expect(revalidatePath).toHaveBeenCalledWith('/findings/finding-7');
    expect(revalidatePath).toHaveBeenCalledWith('/findings');
  });

  it('rejects invalid assignment payloads before calling the controller', async () => {
    const formData = new FormData();
    formData.set('findingId', 'finding-7');
    formData.set('assignee', '   ');

    const result = await assignFindingAction(createInitialActionState(), formData);

    expect(result.status).toBe('error');
    expect(result.message).toMatch(/assignee/i);
    expect(assignFinding).not.toHaveBeenCalled();
    expect(revalidatePath).not.toHaveBeenCalled();
  });

  it('rejects unsupported status transitions before calling the controller', async () => {
    const formData = new FormData();
    formData.set('findingId', 'finding-21');
    formData.set('status', 'invalidated');

    const result = await updateStatusAction(createInitialActionState(), formData);

    expect(result.status).toBe('error');
    expect(result.message).toBe('Select a valid status before updating the workflow.');
    expect(updateFindingStatus).not.toHaveBeenCalled();
  });

  it('only renders status options that the controller accepts', () => {
    render(
      <UpdateStatusForm findingId="finding-21" currentStatus="pending_validation" />
    );

    const options = screen.getAllByRole('option') as HTMLOptionElement[];
    const selectableValues = options
      .filter((option) => !option.disabled)
      .map((option) => option.value);

    expect(selectableValues).toEqual(['open', 'acknowledged', 'resolved']);
    expect(options[0]).toBeDisabled();
    expect(options[0].value).toBe('');
    expect(screen.queryByRole('option', { name: /Invalidated/i })).not.toBeInTheDocument();
  });

  it.each([
    [
      'assignFindingAction',
      assignFindingAction,
      () => {
        const formData = new FormData();
        formData.set('findingId', 'finding-21');
        formData.set('assignee', 'analyst@example.com');
        return formData;
      },
      assignFinding
    ],
    [
      'updateStatusAction',
      updateStatusAction,
      () => {
        const formData = new FormData();
        formData.set('findingId', 'finding-21');
        formData.set('status', 'resolved');
        return formData;
      },
      updateFindingStatus
    ],
    [
      'updateTagsAction',
      updateTagsAction,
      () => {
        const formData = new FormData();
        formData.set('findingId', 'finding-21');
        formData.set('tags', 'scope:risk');
        return formData;
      },
      updateFindingTags
    ],
    [
      'createCommentAction',
      createCommentAction,
      () => {
        const formData = new FormData();
        formData.set('findingId', 'finding-21');
        formData.set('message', 'RBAC regression check');
        return formData;
      },
      createFindingComment
    ],
    [
      'createJiraTicketAction',
      createJiraTicketAction,
      () => {
        const formData = new FormData();
        formData.set('findingId', 'finding-21');
        formData.set('projectKey', 'OPS');
        formData.set('issueType', 'Bug');
        formData.set('summary', 'Restore workflow controls');
        formData.set('description', 'Ensure analysts can update findings.');
        return formData;
      },
      createJiraTicket
    ],
    [
      'createGitHubTicketAction',
      createGitHubTicketAction,
      () => {
        const formData = new FormData();
        formData.set('findingId', 'finding-21');
        formData.set('repository', 'medusa/platform');
        formData.set('title', 'Fix workflow integration');
        formData.set('body', 'Ensure RBAC denials are surfaced.');
        return formData;
      },
      createGitHubTicket
    ]
  ])('surfaces RBAC denials for %s', async (_label, action, buildFormData, apiMock) => {
    const formData = buildFormData();
    const rbacError = new ControllerError('RBAC: analyst role required', 403);
    (apiMock as jest.Mock).mockRejectedValue(rbacError);

    const result = await action(createInitialActionState(), formData);

    expect(result.status).toBe('error');
    expect(result.message).toBe('RBAC: analyst role required');
    expect(revalidatePath).not.toHaveBeenCalled();
  });
});
