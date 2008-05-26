class UsersController < ApplicationController
  before_filter :build_user
  
  def create
    logout_keeping_session!
    if using_open_id?
      session[:user_params] = params[:user] if params[:user]
      authenticate_with_open_id(params[:openid_url], :return_to => open_id_create_url) do |result, identity_url|
        if result.successful?
          create_new_user(session[:user_params].merge(:identity_url => identity_url))
        else
          failed_creation(result.message || "Sorry, something went wrong.")
        end
      end
    else
      create_new_user(params[:user])
    end
  end
  
  protected
  
    def create_new_user(attributes)
      if @user.update_attributes(attributes) && @user.errors.empty?
        successful_creation
      else
        failed_creation
      end
    end
  
    def successful_creation
      # Protects against session fixation attacks, causes request forgery
      # protection if visitor resubmits an earlier form using back
      # button. Uncomment if you understand the tradeoffs.
      # reset session
      self.current_user = @user # !! now logged in
      redirect_back_or_default('/')
      flash[:notice] = "Thanks for signing up!"
    end
    
    def failed_creation(message = "We couldn't set up that account, sorry.")
      flash[:error] = message 
      render :action => 'new'
    end
    
    def build_user
      @user = User.new      
    end
end
