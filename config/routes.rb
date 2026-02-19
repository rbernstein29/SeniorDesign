# config/routes.rb
Rails.application.routes.draw do
  resource :session
  resources :passwords, param: :token

  # Pages
  root "pages#home"
  get "/app",     to: "pages#app"
  get "/home",    to: "pages#home"
  get "/scanner", to: "pages#scanner"

  # Assets
  resources :assets, only: [:index, :new, :create, :show], path: 'scan-assets'

  # Agents
  resources :agents, only: [:index, :create, :destroy] do
    member do
      get :download
    end
  end

  namespace :api do
    resources :users, only: [:index, :show, :create] do
      collection do
        post :signin
        post :signout
      end
    end
    resources :organizations, only: [:index, :show, :create]
    resources :accounts, only: [:create]
  end

  get "up" => "rails/health#show", as: :rails_health_check
end