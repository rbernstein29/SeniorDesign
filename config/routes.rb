# config/routes.rb
Rails.application.routes.draw do
  resource :session, only: [:new, :create, :destroy]
  resources :passwords, param: :token

  # Pages
  root "pages#home"
  get "/login",    to: "pages#login"
  get "/home",     to: "pages#home"
  get "/scanner",  to: "pages#scanner"
  get "/scans",    to: "pages#scans",    as: :scans
  get "/reports",  to: "pages#reports",  as: :reports
  get "/settings", to: "pages#settings", as: :settings

  # Assets
  resources :assets, only: [:index, :new, :create, :show], path: 'scan-assets'

  # Agents
  resources :agents, only: [:index, :create, :destroy] do
    member do
      get :download
    end
  end
  post 'agents/:agent_id/heartbeat', to: 'agents#heartbeat', as: :agent_heartbeat

  # Accounts
  resources :accounts, only: [:create]
  resources :reports, only: [:index, :show, :create]

  get "up" => "rails/health#show", as: :rails_health_check
end
