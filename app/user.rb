# frozen_string_literals: true

module GritsosAPI
  class User
    # Create a new user.
    #
    # user - a hash of user.
    
    def initialize(user = nil)
      if user.nil?
        @privileged = false
        @user = nil
      else
        p user[:password]
        @privileged = !user.delete(:password).nil?
        @user = user.dup
      end
    end
    
    # By implementing #nil? the User class may represent the nil user. A nil, or
    # blank user is created by passing either no argument or nil to .new.
    
    def nil?
      @user.is_a? Hash
    end
    
    # A user object is considered valid if it contains an id, username and auth
    # token.
    #
    # Returns true if the user is valid and false otherwise.
    
    def valid?
      @user.has_key?(:id) && @user.has_key?(:username) && @user.has_key?(:token)
    rescue NoMethodError
      false
    end
    
    # Access all user attributes stored in the user. This supports any key that
    # was passed to .new thereby allows for arbitrary keys to be used. The
    # method will raise an exception if the key does not exist though.
    
    def [](key)
      @user.fetch key
    end
    
    # Accessor method for the user id.
    
    def id
      self[:id]
    end
    
    # Accessor method for the username.
    
    def username
      self[:username]
    end
    
    # Accessor method for the user token.
    
    def token
      self[:token]
    end
    
    def privileged?
      @privileged
    end
    
    # Compare a user with another. Two users are considered equal if their
    # usernames match.
    #
    # other - any object that returns a username string when called either on
    # #username or #string.
    
    def ==(other)
      if other.respond_to?(:username)
        username == other.username
      else
        username == other.to_s
      end
    end
    
    # Format the user as a JSON record.
    #
    # Returns a string.
    
    def to_json(*args)
      {
        username: self[:username],
        token: self[:token]
      }.to_json(*args)
    end
  end
end
