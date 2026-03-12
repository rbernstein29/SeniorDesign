# Add your own tasks in files placed in lib/tasks ending in .rake,
# for example lib/tasks/capistrano.rake, and they will automatically be available to Rake.

require_relative "config/application"

Rails.application.load_tasks

# Skip JS build steps when running tests without npm/node installed
if Rails.env.test?
  %w[javascript:install javascript:build].each do |task|
    Rake::Task[task].clear if Rake::Task.task_defined?(task)
    task(task) {}
  end
end
