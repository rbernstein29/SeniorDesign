class AddUniquenessConstraints < ActiveRecord::Migration[8.0]
  def change
    # Org names must be globally unique (case-insensitive)
    execute "CREATE UNIQUE INDEX index_organizations_on_lower_org_name ON vuln_scanner.organizations (lower(org_name));"
    # Emails must be unique within an org (same email fine across different orgs)
    execute "CREATE UNIQUE INDEX IF NOT EXISTS index_users_on_email_and_org ON vuln_scanner.users (lower(email_address), organization_id);"
  end
end
