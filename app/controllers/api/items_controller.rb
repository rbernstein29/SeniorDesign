module Api
  class ItemsController < ApplicationController
    skip_before_action :verify_authenticity_token
 
    # GET /api/items
    def index
      items = Item.all
      render json: items
    end

    # GET /api/items/:id
    def show
      item = Item.find(params[:id])
      render json: item
    end

    # POST /api/items
    def create
      puts "PARAMS: #{params.inspect}"
      item = Item.new(item_params)
      if item.save
        render json: item, status: :created
      else
        render json: { errors: item.errors.full_messages }, status: :unprocessable_entity
      end
    end
 
    def item_params
      params.require(:item).permit(:name, :description)
    end

  end
end
