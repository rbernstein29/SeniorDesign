require "test_helper"

class ActivityLogTest < ActiveSupport::TestCase
  test "for_org scope filters by organization_id" do
    org = organizations(:acme)
    log = ActivityLog.create!(organization_id: org.id, user_id: users(:admin_user).id,
                              color: "blue", text: "scoped")
    assert_includes ActivityLog.for_org(org.id), log
  end

  test "after_create prune retains only the LIMIT_PER_ORG most recent" do
    org_id = organizations(:acme).id
    ActivityLog.where(organization_id: org_id).delete_all
    (ActivityLog::LIMIT_PER_ORG + 5).times do |i|
      ActivityLog.create!(organization_id: org_id, user_id: users(:admin_user).id,
                          color: "blue", text: "evt #{i}")
    end
    assert_equal ActivityLog::LIMIT_PER_ORG,
                 ActivityLog.where(organization_id: org_id).count
  end

  test "prune rescues internal errors" do
    org_id = organizations(:acme).id
    log = ActivityLog.new(organization_id: org_id, user_id: users(:admin_user).id,
                          color: "blue", text: "boom")
    log.stub(:organization_id, ->(*) { raise "boom" }) do
      assert_nothing_raised { log.send(:prune_old_entries) }
    end
  end
end
