package authz

const (
	RoleAdmin = "admin"
	RoleRO    = "ro"
)

const (
	PermPoliciesRead   = "policies.read"
	PermPoliciesWrite  = "policies.write"
	PermPoliciesCreate = "policies.create"
	PermPoliciesDelete = "policies.delete"

	PermGroupsRead   = "groups.read"
	PermGroupsWrite  = "groups.write"
	PermGroupsCreate = "groups.create"
	PermGroupsDelete = "groups.delete"

	PermUsersRead   = "users.read"
	PermUsersWrite  = "users.write"
	PermUsersCreate = "users.create"
	PermUsersDelete = "users.delete"

	PermTokensRead   = "tokens.read"
	PermTokensCreate = "tokens.create"
	PermTokensDelete = "tokens.delete"

	PermIntegrationsRead  = "integrations.read"
	PermIntegrationsWrite = "integrations.write"
)

func Permissions(role string) map[string]bool {
	switch role {
	case RoleAdmin:
		return map[string]bool{
			PermPoliciesRead: true, PermPoliciesWrite: true, PermPoliciesCreate: true, PermPoliciesDelete: true,
			PermGroupsRead: true, PermGroupsWrite: true, PermGroupsCreate: true, PermGroupsDelete: true,
			PermUsersRead: true, PermUsersWrite: true, PermUsersCreate: true, PermUsersDelete: true,
			PermTokensRead: true, PermTokensCreate: true, PermTokensDelete: true,
			PermIntegrationsRead: true, PermIntegrationsWrite: true,
		}
	default:
		return map[string]bool{
			PermPoliciesRead:     true,
			PermGroupsRead:       true,
			PermUsersRead:        true,
			PermTokensRead:       true,
			PermIntegrationsRead: true,
		}
	}
}

func ValidRole(r string) bool { return r == RoleAdmin || r == RoleRO }

func EffectiveRole(userRole, groupRole string) string {
	if userRole == RoleAdmin || groupRole == RoleAdmin {
		return RoleAdmin
	}
	return RoleRO
}
