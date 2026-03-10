class RenameOrgIdToOrganizationId < ActiveRecord::Migration[8.0]
  def up
    execute <<~SQL
      DO $$
      BEGIN
        -- sites: rename if only org_id exists; drop org_id if organization_id already exists
        IF EXISTS (SELECT 1 FROM information_schema.columns WHERE table_schema='vuln_scanner' AND table_name='sites' AND column_name='org_id')
           AND NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_schema='vuln_scanner' AND table_name='sites' AND column_name='organization_id') THEN
          ALTER TABLE vuln_scanner.sites RENAME COLUMN org_id TO organization_id;
        ELSIF EXISTS (SELECT 1 FROM information_schema.columns WHERE table_schema='vuln_scanner' AND table_name='sites' AND column_name='org_id') THEN
          ALTER TABLE vuln_scanner.sites DROP COLUMN org_id;
        END IF;

        -- assets: rename if only org_id exists; drop duplicate org_id if organization_id already exists
        IF EXISTS (SELECT 1 FROM information_schema.columns WHERE table_schema='vuln_scanner' AND table_name='assets' AND column_name='org_id')
           AND NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_schema='vuln_scanner' AND table_name='assets' AND column_name='organization_id') THEN
          ALTER TABLE vuln_scanner.assets RENAME COLUMN org_id TO organization_id;
        ELSIF EXISTS (SELECT 1 FROM information_schema.columns WHERE table_schema='vuln_scanner' AND table_name='assets' AND column_name='org_id') THEN
          ALTER TABLE vuln_scanner.assets DROP COLUMN org_id;
        END IF;
      END $$;
    SQL
  end

  def down
    # no-op
  end
end
