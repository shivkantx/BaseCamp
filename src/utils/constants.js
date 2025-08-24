// User roles enum
export const UserRolesEnum = Object.freeze({
  ADMIN: "admin",
  PROJECT_ADMIN: "project_admin",
  MEMBER: "member",
});

// All available roles as an array
export const AvailableUserRoles = Object.values(UserRolesEnum);

// Task status enum
export const TaskStatusEnum = Object.freeze({
  TODO: "todo",
  IN_PROGRESS: "in_progress",
  DONE: "done",
});

// All available task statuses as an array
export const AvailableTaskStatuses = Object.values(TaskStatusEnum);
