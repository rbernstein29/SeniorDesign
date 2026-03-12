# config/routes.rb
Rails.application.routes.draw do
  resource :session, only: [:new, :create, :destroy]
  resources :passwords, param: :token

  # Pages
  root "pages#home"
  get "/login",    to: "pages#login"
  get "/home",     to: "pages#home"
  get "/scanner",  to: "pages#scanner"
  post "/scanner/trigger", to: "pages#trigger_scan", as: :trigger_scan
  get "/scans",    to: "pages#scans",    as: :scans
  post "/scans/stop", to: "pages#stop_scan", as: :stop_scan
  get "/reports",  to: "pages#reports",  as: :reports
  get "/settings", to: "pages#settings", as: :settings
  get "/read_only_accounts", to: "pages#read_only_accounts", as: :read_only_accounts
  get "/create_ro_account", to: "pages#create_ro_account", as: :create_ro_account
  delete "/read_only_accounts/:id", to: "read_only_accounts#destroy", as: :delete_read_only_account

  # Sites
  resources :sites, only: [:index, :create, :destroy]

  # Assets
  resources :assets, only: [:index, :new, :create, :show, :destroy], path: 'scan-assets'

  # Agents
  resources :agents, only: [:index, :create, :destroy] do
    member do
      get :download
    end
    collection do
      get :status
    end
  end
  post 'agents/:agent_id/heartbeat', to: 'agents#heartbeat', as: :agent_heartbeat

  # Accounts
  resources :accounts, only: [:create]
  resources :read_only_accounts, only: [:create]
  resources :reports, only: [:destroy]

  # Api
  namespace :api do
    scope ':api_key' do
      # Reports endpoint: /api/{key}/reports
      resources :reports_api, only: [:index, :show], path: 'reports'
    end
  end
  patch '/accounts/generate_api_key', to: 'accounts#generate_api_key', as: :generate_api_key

  get "up" => "rails/health#show", as: :rails_health_check
end
