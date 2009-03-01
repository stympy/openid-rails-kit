require 'digest/sha1'

class User < ActiveRecord::Base
  include Authentication
  include Authentication::ByPassword
  include Authentication::ByCookieToken


  validates_presence_of     :login,    :if => :not_using_openid?
  validates_length_of       :login,    :within => 3..40, :if => :not_using_openid?
  validates_uniqueness_of   :login,    :case_sensitive => false, :if => :not_using_openid?
  validates_format_of       :login,    :with => RE_LOGIN_OK, :message => MSG_LOGIN_BAD, :if => :not_using_openid?

  validates_format_of       :name,     :with => RE_NAME_OK,  :message => MSG_NAME_BAD, :allow_nil => true
  validates_length_of       :name,     :maximum => 100

  validates_presence_of     :email
  validates_length_of       :email,    :within => 6..100 #r@a.wk
  validates_uniqueness_of   :email,    :case_sensitive => false
  validates_format_of       :email,    :with => RE_EMAIL_OK, :message => MSG_EMAIL_BAD
  
  validates_uniqueness_of   :identity_url, :unless => :not_using_openid?

  validate :normalize_identity_url

  # HACK HACK HACK -- how to do attr_accessible from here?
  # prevents a user from submitting a crafted form that bypasses activation
  # anything else you want your user to change should be added here.
  attr_accessible :login, :email, :name, :password, :password_confirmation, :identity_url



  # Authenticates a user by their login name and unencrypted password.  Returns the user or nil.
  #
  # uff.  this is really an authorization, not authentication routine.  
  # We really need a Dispatch Chain here or something.
  # This will also let us return a human error message.
  #
  def self.authenticate(login, password)
    u = find_by_login(login) # need to get the salt
    u && u.authenticated?(password) ? u : nil
  end
  
  def not_using_openid?
    identity_url.blank?
  end

  def password_required?
    new_record? ? not_using_openid? && (crypted_password.blank? || !password.blank?) : !password.blank?
  end

  protected
    
    def normalize_identity_url
      self.identity_url = OpenIdAuthentication.normalize_identifier(identity_url) unless identity_url.blank?
    rescue URI::InvalidURIError
      errors.add_to_base("Invalid OpenID URL")
    end

end
