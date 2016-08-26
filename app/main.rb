# frozen_string_literal: true

require 'json'
require 'sequel'

require 'sinatra/base'
require 'sinatra/json'

require 'app/auth'
require 'app/user'
require 'app/model'

module GritsosAPI
  class App < Sinatra::Base

    # Use the dotenv gem to load environment variables from the .env file during
    # development, as a standin for the docker env_file option used in
    # production.
    
    configure :development do
      require 'dotenv'
      Dotenv.load!
      
      enable :logging
      set :show_exceptions, :after_handler
    end
    
    # Setup the database connection and configure:
    # - server
    
    configure do
      set :server, :thin

      db = Sequel.mysql2 ENV['DB_DATABASE'],
                         user: ENV['DB_USERNAME'],
                         password: ENV['DB_PASSWORD'],
                         host: ENV['DB_HOSTNAME']

      set :database, db
    end
    
    # Error handler for all 4XX and 5XX error codes. The response body is simply
    # wrapped in a JSON object.
    
    error 400...600 do
      json error: response.body.join
    end
    
    # Helpers
    
    helpers Model, Auth
        
    # Get user information, either for yourself (user used to authenticate) or
    # for any other user. Note that that requires level 1 clearance.
    #
    # This is a protected API call that requires authentication. Both a token
    # and a password is accepted.
    #
    # This call accepts the username, ordered by precedence, either
    # a) as the query key 'user'
    # b) as the query key 'username'
    # c) as the currently authenticated user (no additional argument)
    #
    # The respons includes user information and is JSON formatted.
    #
    # Example
    #   GET /user?username=level_1_user&password=xxxx&user=level_0_user
    #   => {
    #        username: level_0_user,
    #        level: 0,
    #        token: <token>
    #      }
    
    get '/user' do
      authenticate! methods: [:token, :password]
      
      username = params['user'] || params['username']
      
      user =
        if username.nil? || current_user == username
          current_user
        else
          halt 403 unless current_user.privileged?
          find_user username
        end
      
      halt 404 unless user # Not found
      
      json user
    end
    
    # Users with level 1 clearance may create new users by posting a username
    # and an optional password. If a password is not given the new user will
    # only be able to authenticate via token.
    
    post '/user' do
      authenticate! 1
      
      halt 400 unless params['username'] # Bad request
      
      halt 403 unless current_user.privileged? # Forbidden
      
      user = create_user(params['username'], params['password'], 0)
      
      halt 500 unless user # Internal Server Error
      
      status 201 # Created
      
      json user
    end
    
    # Get a list of all physical devices that are registered.
    
    get '/devices' do
      authenticate!
      
      'devices'
    end
    
    # Get a list of all sensors that are available through devices.
    
    get '/sensors' do
      authenticate!
      
      'sensors'
    end
    
    # Access sensor readings.
    #
    # This call does not require authentication.

    get '/sensor/:id' do |id|
      # - Make sure id is numeric
      # data = fetch_sensor_data id, from: params[:from], upto: params[:to]
      
      'sensor'
    end
    
    # Post new sensor readings.
    #
    # This call requires authentication.
    
    post '/sensor' do
      authenticate!
      
      'ok'
    end
  end
end