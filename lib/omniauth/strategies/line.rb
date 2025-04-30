require 'omniauth-oauth2'
require 'json'
require 'net/http'
require 'uri'

module OmniAuth
  module Strategies
    class Line < OmniAuth::Strategies::OAuth2
      option :name, 'line'
      option :scope, 'profile openid email'

      option :client_options, {
        site: 'https://access.line.me',
        authorize_url: '/oauth2/v2.1/authorize',
        token_url: '/oauth2/v2.1/token'
      }

      # Add bot_prompt parameter to authorization request
      option :authorize_options, [:bot_prompt]

      # host changed
      def callback_phase
        options[:client_options][:site] = 'https://api.line.me'
        super
      end

      def callback_url
        # Fixes regression in omniauth-oauth2 v1.4.0 by https://github.com/intridea/omniauth-oauth2/commit/85fdbe117c2a4400d001a6368cc359d88f40abc7
        options[:callback_url] || (full_host + script_name + callback_path)
      end

      # Override to include bot_prompt parameter and ensure scope is properly set
      def authorize_params
        super.tap do |params|
          # Set bot_prompt to aggressive if specified
          params[:bot_prompt] = 'aggressive' if options[:bot_prompt] == 'aggressive'
        end
      end

      uid { raw_info['userId'] }

      info do
        {
          name:        raw_info['displayName'],
          image:       raw_info['pictureUrl'],
          description: raw_info['statusMessage'],
          email:       verify_id_token['email'] # 使用verify_id_token方法獲取電子郵件
        }
      end

      # 驗證ID令牌並返回解碼的結果
      def verify_id_token
        id_token = access_token.params['id_token']
        uri = URI('https://api.line.me/oauth2/v2.1/verify')

        req = Net::HTTP::Post.new(uri.path, {'Content-Type' => 'application/x-www-form-urlencoded'})
        req.set_form_data('id_token' => id_token, 'client_id' => options.client_id)

        res = Net::HTTP.start(uri.hostname, uri.port, use_ssl: true) do |http|
          http.request(req)
        end

        JSON.parse(res.body)
      end

      # Require: Access token with PROFILE permission issued.
      def raw_info
        @raw_info ||= JSON.load(access_token.get('v2/profile').body)
      rescue ::Errno::ETIMEDOUT
        raise ::Timeout::Error
      end

    end
  end
end
