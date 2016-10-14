require 'sinatra'
#require 'omniauth-google-oauth2'
require 'pry'
require 'dotenv'
Dotenv.load

set :port, 9393


require 'omniauth-oauth2'
require 'omniauth'

module OmniAuth
  module Strategies
    class WeekDone < OmniAuth::Strategies::OAuth2

      # Give your strategy a name.
      option :name, "weekdone"

      # This is where you pass the options you would pass when
      # initializing your consumer from the OAuth gem.
      option :client_options, {
        :site => "https://weekdone.com/",
        :redirect_uri =>"http://localhost:9393/auth/weekdone/callback",
        :authorize_url => "https://weekdone.com/oauth_authorize",
        :token_url => "https://weekdone.com/oauth_token"}

      #strip out any query params
      def callback_url
        full_host + script_name + callback_path
      end

      #binding.pry
      #uid{access_token.params['uid'] }


      # These are called after authentication has succeeded. If
      # possible, you should try to set the UID without making
      # additional calls (if the user id is returned with the token
      # or as a URI parameter). This may not be possible with all
      # providers.
      uid{ raw_info['id'] }
      info do
        {
          :name => raw_info['name'],
          :email => raw_info['email']
        }
      end

      extra do
        {
          'raw_info' => raw_info
        }
      end

      def raw_info
        @raw_info ||= access_token.params['user']
      end
    end
  end
end


class WeekDoneClient
  require 'rest-client'

  # Initializes a new client object
  #
  # @param token [String] The auth token
  # @return WeekDoneClient
  def initialize(token)
    @token = token
  end

  # Get all tags
  #
  # @return [Hash] Tag names mapped to IDs (for easy scanning)
  def tags
    tag_hash = {}
    JSON.parse(RestClient.get "https://api.weekdone.com/1/tag", {:params => {:token=>@token}})['tags'].map{|tag| tag_hash[tag['tag']] = tag['id']}
    tag_hash
  end

  def get_comments(objective_id)
      get "https://api.weekdone.com/1/companyobjective/#{objective_id}/comments"
  end

  # Get a raw url passing in the token as a param
  #
  # @param url [String] @return [Hash] Tag names mapped to IDs (for easy scanning)
  def get(url, extra_params = {})
    JSON.parse(RestClient.get url, {:params => {:token=>@token}.merge!(extra_params)})
  end

  # Generic getter of weekdone things.
  #
  # @param type [String] type The type of thing you're getting. Try "users", "tags", "items"
  def get_things(type, search_params={})
    type = type.to_s.downcase
    data = JSON.parse(RestClient.get "https://api.weekdone.com/1/" + type, {:params => {:token=>@token}.merge!(search_params)})
    #return the inside hash named after our object (e.g. data['users']) if there is one
    #otherwise, just return the raw data
    data[type].nil? ? data : data[type]
  end

  # Get all users
  #
  # @return [Array]
  def users
    get_things :users
  end
end

use Rack::Session::Cookie
#use OmniAuth::Strategies::Developer
#use OmniAuth::Strategies::WeekDone

use OmniAuth::Builder do
  provider :WeekDone, ENV['WEEKDONE_CLIENT_ID'],ENV['WEEKDONE_CLIENT_SECRET']
end

use Rack::Session::Cookie, secret: 'abcdefg-Peter-Kappus'
enable :sessions

get '/auth/weekdone/callback' do
  session['token'] = request.env['omniauth.auth']['credentials']['token'].to_s
  #session['token']
  #binding.pry
  "<h1>Hello! " + request.env['omniauth.auth']['info']['name'] + "</h1>" + "<h2>Tags:</h2> <h3> " +   WeekDoneClient.new(session['token']).tags.keys.to_s + "</h3> <h2> Users: </h2> <h3> " + WeekDoneClient.new(session['token']).users.map{|u| u['name']}.to_s + "</h3>"
end

get '/tags' do
  client.tags.keys.to_s
end

get '/comments' do

end

get '/company_goals' do
  #client.
end

get '/pry' do
  #use 'client' interactively
  binding.pry
  #"<meta http-equiv='refresh' content='5'/> <h1>Go look at your terminal!"
end

get '/people' do
  client.users.to_s
end

get '/token' do
    session['token'].to_s
end

get '/' do
  #"<a href='/auth/weekdone'>Sign in with WeekDone</a>"
  redirect to('/auth/weekdone')
end

private

def client
  WeekDoneClient.new(session['token'])
end
