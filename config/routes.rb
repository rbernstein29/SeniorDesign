# config/routes.rb
Rails.application.routes.draw do
  resource :session, only: [:new, :create, :destroy]
  resources :passwords, param: :token

  # Pages
  root "pages#home"
  get "/login",    to: "pages#login"
  get "/home",     to: "pages#home"
  get '/home/recent_findings', to: 'pages#home_recent_findings', as: :home_recent_findings
  get '/home/stats',           to: 'pages#home_stats',           as: :home_stats
  get "/scanner",  to: "pages#scanner"
  post "/scanner/trigger", to: "pages#trigger_scan", as: :trigger_scan
  get "/scans",        to: "pages#scans",       as: :scans
  get "/scans/status", to: "pages#scans_status", as: :scans_status
  post "/scans/stop",  to: "pages#stop_scan",    as: :stop_scan
  get "/reports",  to: "pages#reports",  as: :reports
  get "/settings",  to: "pages#settings",  as: :settings
  get "/api-docs",  to: "pages#api_docs",  as: :api_docs
  get "/read_only_accounts", to: "pages#read_only_accounts", as: :read_only_accounts
  get "/create_ro_account", to: "pages#create_ro_account", as: :create_ro_account
  delete "/read_only_accounts/:id", to: "read_only_accounts#destroy", as: :delete_read_only_account

  # Sites
  resources :sites, only: [:index, :create, :destroy]

  # Assets
  resources :assets, only: [:index, :new, :create, :show, :destroy], path: 'scan-assets'

  # Scan Profiles
  resources :scan_profiles, only: [:index, :new, :create, :destroy]

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
  get '/verify_email/:token', to: 'accounts#verify_email', as: :verify_email
  get '/verify_pending', to: 'accounts#verify_pending', as: :verify_pending
  post '/resend_verification', to: 'accounts#resend_verification', as: :resend_verification
  resources :accounts, only: [:create, :destroy]
  resources :read_only_accounts, only: [:create]
  resources :reports, only: [:show, :destroy] do
    member do
      get  :download_json
      get  :download_xlsx
      get  :download_csv
      get  :download_whitebox_json
      get  :data
      post :retest
    end
  end

  resources :findings, only: [] do
    member do
      post :ai_remediation
    end
  end

  get  '/code-analysis', to: 'code_analysis#index',   as: :code_analysis
  post '/code-analysis', to: 'code_analysis#analyze', as: :code_analysis_submit

  # Api
  namespace :api do
    scope ':api_key' do
      resources :reports_api, only: [:index, :show, :destroy], path: 'reports' do
        member do
          get  :download_json
          get  :download_xlsx
          get  :download_csv
          get  :download_whitebox_json
          get  :data
          post :retest
        end
      end

      resources :assets_api,        only: [:index, :show, :create, :destroy], path: 'assets'
      resources :sites_api,         only: [:index, :create, :destroy],        path: 'sites'
      resources :scan_profiles_api, only: [:index, :create, :destroy],        path: 'scan-profiles'

      resources :scans_api, only: [:index, :show], path: 'scans' do
        collection do
          post :trigger
          post :stop
        end
      end

      resources :findings_api, only: [:index, :show], path: 'findings' do
        member do
          post :ai_remediation
        end
      end

      resources :exploits_api, only: [:index, :show], path: 'exploits' do
        collection do
          get :count
        end
      end

      post 'code-analysis', to: 'code_analysis_api#analyze', as: :api_code_analysis

      resources :agents_api, only: [:index, :create, :destroy], path: 'agents' do
        member do
          get :download
        end
        collection do
          get :status
        end
      end

      get 'account', to: 'account_api#show'
    end
  end
  patch '/accounts/generate_api_key', to: 'accounts#generate_api_key', as: :generate_api_key
  get '/exploits/count', to: 'exploits#count', as: :exploit_count

  get "up" => "rails/health#show", as: :rails_health_check
end
