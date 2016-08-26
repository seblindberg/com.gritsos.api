require 'bcrypt'

module GritsosAPI
  module Model
    
    def model(table)
      settings.database[table]
    end
    
    # Fetch the user with the given id.
    #
    # id - integer user id.
    #
    # Returns the id, username and access level of the user, or nil if no user
    # exist with that id.
    
    def fetch_user(id)
      record =
        model(:users)
          .select(:id, :username, :level)
          .where(id: id)
          .first
      User.new record
    end
    
    # Find the user with the given username.
    #
    # username - the username of a user.
    # password - optional password that will be matched against that of the
    #            user.
    #
    # Returns a hash containing id, username and auth level of the requested
    # user, or nil if no user is found that matches the given arguments.
    
    def find_user(username, password = nil)
      record =
        model(:users)
          .left_join(:tokens, :users__id => :tokens__user_id)
          .select(:users__id___id, :username, :password, :token, :level)
          .where(username: username)
          .first

      return unless record
      
      # Make sure we don't leak the password to the caller
      stored_pwd = record[:password]
      
      return unless BCrypt::Password.new(stored_pwd) == password if password
      
      # Create a token if one doesn't exist yet. One really
      # should, but just to be safe we check.
      record[:token] = create_token record[:id] unless record[:token]
      
      User.new record
    end
    
    # Create a new user in the database. This method will halt if an error
    # occurred.
    #
    # username - the unique username of the user.
    # password - a non empty string, or nil.
    # level - the access level of the user.
    #
    # Returns the newly created user, including a new token.
    
    def create_user(username, password = nil, level = 0)
      logger.info "Creating new user #{username}"
      
      hashed_password =
        if password
          return if password.empty?
          BCrypt::Password.create(password)
        else
          nil
        end
        
      id = nil
      token = generate_token
      
      settings.database.transaction do
        # Create user
        id = model(:users).insert({
          username: username,
          password: hashed_password,
          level: level,
        })
        
        # Create token
        model(:tokens).insert({
          user_id: id,
          token: token
        })
      end
      
      User.new id: id,
               username: username,
               password: hashed_password,
               token: token,
               level: level
    
    rescue Sequel::UniqueConstraintViolation => e
      halt 409, e.message # Conflict
    end
    
    # Find the user with the given token.
    #
    # token - the token of a user.
    #
    # Returns a hash containing id, username, token and auth level of the
    # requested user.
    
    def find_user_with_token(token)
      record =
        model(:users)
          .join(:tokens, :users__id => :tokens__user_id)
          .select(:users__id___id, :username, :password, :token, :level)
          .where(token: token)
          .first

      User.new record
    end
    
    # Find the token used by the user with the given id.
    #
    # user_id - the id of a user.
    #
    # Returns the token as a string, or nil if no token exist.
    
    def find_token(user_id)
      record =
        model(:tokens)
          .select(:token)
          .where(user_id: user_id)
          .first

      record[:token]
    end
    
    # Create a new token and insert it into the database. This method relies
    # upon #generate_token being available in the current scope.
    #
    # user_id - the id of a user.
    #
    # Returns the new token.
    
    def create_token(user_id)
      logger.info "Creating new user token for user id #{user_id}"
      
      token = generate_token
      
      settings.database.transaction do
        # Invalidate any pre existing token
        model(:tokens)
          .where(user_id: user_id)
          .update(user_id: nil)
          
        model(:tokens).insert({
          user_id: user_id,
          token: token
        })
      end
      
      token
    end
  end
end