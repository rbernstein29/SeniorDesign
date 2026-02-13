Rails.application.routes.draw do
  resource :session
  resources :passwords, param: :token
  # Define your application routes per the DSL in https://guides.rubyonrails.org/routing.html

  resources :assets, only: [:index, :new, :create, :show], path: 'scan-assets'
  
  # Homepage
  root "pages#app"

  # Additional roots here
  get "/app", to: "pages#app"
  get "/home", to: "pages#home"
  get "/scan", to: "pages#scan_config"
  get "/assets", to: "assets#index"

  namespace :api do 
    resources :users, only: [:index, :show, :create,] do
      collection do
        post :signin
        post :signout
      end
    end

    resources :organizations, only: [:index, :show, :create]
    resources :accounts, only: [:create]

  end
  # Reveal health status on /up that returns 200 if the app boots with no exceptions, otherwise 500.
  # Can be used by load balancers and uptime monitors to verify that the app is live.
  get "up" => "rails/health#show", as: :rails_health_check
  # Render dynamic PWA files from app/views/pwa/* (remember to link manifest in application.html.erb)
  # get "manifest" => "rails/pwa#manifest", as: :pwa_manifest
  # get "service-worker" => "rails/pwa#service_worker", as: :pwa_service_worker

  # Defines the root path route ("/")
  # root "posts#index"
end
