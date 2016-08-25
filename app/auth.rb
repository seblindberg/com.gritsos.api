require 'bcrypt'
require 'securerandom'

module GritsosAPI
  module Auth
    class Unautharized < StandardError; end
    
    # Authenticate the request against the users and tokens stored in the
    # database. First, the existance of a TOKEN in the HTTP headers will be
    # checked. If it is set, it will be used for authentication.
    #
    # If the TOKEN header is not set, the request will instead be validated
    # using username and password. For this to work, the username and password
    # must be be available as params.
    
    def authenticate!(level = 0, methods: [:token])
      user =
        if methods.include?(:token) && valid_token?
          logger.info 'Auth using token'
          env['gritsos.auth.method'] = :token
          
          find_user_with_token env['HTTP_TOKEN']
            
        elsif methods.include?(:password) && valid_user?
          logger.info 'Auth using username and password'
          env['gritsos.auth.method'] = :password

          find_user params['username'], params[:password]
        else
          halt 400, 'A token or password is required for authentication'
        end

      halt 401 unless user                  # Unauthorized
      halt 403 unless level <= user[:level] # Forbidden
      
      env['gritsos.user'] = user
    end
    
    # Check if the request contains valid user credentials.
    #
    # Returns true if both username and password are present in the request
    # params.
    
    def valid_user?
      params['username'] && params['password']
    end
    
    # Check if the request contains a valid user token.
    #
    # Returns true if a user token is present in the HTTP request header.
    
    def valid_token?
      env['HTTP_TOKEN']
    end
    
    def current_user
      env['gritsos.user']
    end
    
    alias user current_user
    
    # Access the current user level.
    
    def user_level
      env['gritsos.user'][:level]
    end
    
    def user_privileged?
      
    end
    
    # Generates a random token encoded in base64.
    #
    # Returns a 48 character string of random letters within the base64 charset.
    
    def generate_token(length = 48)
      SecureRandom.base64(length)
    end
  end
end