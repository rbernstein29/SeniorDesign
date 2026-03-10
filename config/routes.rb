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
  get "/reports",  to: "pages#reports",  as: :reports
  get "/settings", to: "pages#settings", as: :settings

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
  resources :reports, only: [:destroy]

  # Api
  namespace :api do
    scope ':api_key' do
      resources :reports_api, only: [:index, :show]
    end
  end
  patch '/accounts/generate_api_key', to: 'accounts#generate_api_key', as: :generate_api_key

  get "up" => "rails/health#show", as: :rails_health_check
end
