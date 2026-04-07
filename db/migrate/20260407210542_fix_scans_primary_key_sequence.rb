class FixScansPrimaryKeySequence < ActiveRecord::Migration[8.0]
  def up
    execute "ALTER TABLE scans ALTER COLUMN id SET DEFAULT nextval('scans_id_seq'::regclass);"
    execute "SELECT setval('scans_id_seq', (SELECT MAX(id) FROM scans) + 1);"

    execute "ALTER TABLE scan_exploits ALTER COLUMN id SET DEFAULT nextval('scan_exploits_id_seq'::regclass);"
    execute "SELECT setval('scan_exploits_id_seq', (SELECT MAX(id) FROM scan_exploits) + 1);"

    execute "ALTER TABLE scan_targets ALTER COLUMN id SET DEFAULT nextval('scan_targets_id_seq'::regclass);"
    execute "SELECT setval('scan_targets_id_seq', (SELECT MAX(id) FROM scan_targets) + 1);"
  end

  def down
    raise ActiveRecord::IrreversibleMigration
  end
end
