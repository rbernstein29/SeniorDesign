class RenameOrgIdToOrganizationId < ActiveRecord::Migration[8.0]
  def up
    execute <<~SQL
      DO $$
      BEGIN
        IF EXISTS (
          SELECT 1 FROM information_schema.columns
          WHERE table_schema = 'vuln_scanner' AND table_name = 'sites' AND column_name = 'org_id'
        ) THEN
          ALTER TABLE vuln_scanner.sites RENAME COLUMN org_id TO organization_id;
        END IF;

        IF EXISTS (
          SELECT 1 FROM information_schema.columns
          WHERE table_schema = 'vuln_scanner' AND table_name = 'assets' AND column_name = 'org_id'
        ) THEN
          ALTER TABLE vuln_scanner.assets RENAME COLUMN org_id TO organization_id;
        END IF;
      END $$;
    SQL
  end

  def down
    execute <<~SQL
      DO $$
      BEGIN
        IF EXISTS (
          SELECT 1 FROM information_schema.columns
          WHERE table_schema = 'vuln_scanner' AND table_name = 'sites' AND column_name = 'organization_id'
        ) THEN
          ALTER TABLE vuln_scanner.sites RENAME COLUMN organization_id TO org_id;
        END IF;

        IF EXISTS (
          SELECT 1 FROM information_schema.columns
          WHERE table_schema = 'vuln_scanner' AND table_name = 'assets' AND column_name = 'organization_id'
        ) THEN
          ALTER TABLE vuln_scanner.assets RENAME COLUMN organization_id TO org_id;
        END IF;
      END $$;
    SQL
  end
end
