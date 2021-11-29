# frozen_string_literal: true

require 'securerandom'
require 'base64'
require 'json'

module Kafka
  module Sasl
    class AwsMskIamCredential
      # an instance of this class is returned with refreshed credentials from the
      # AwsMskIamConfig#get_credentials call.

      def initialize(aws_region:, access_key_id:, secret_key_id:, session_token: nil, 
        role_arn: nil, role_session_name: nil, duration_sec: 900)
        @aws_region = aws_region
        @access_key_id = access_key_id
        @secret_key_id = secret_key_id
        @session_token = session_token
        @role_arn = role_arn
        @role_session_name = role_session_name
        @duration_sec = duration_sec
      end

      def get_aws_region
        @aws_region
      end

      def get_access_key_id
        @access_key_id
      end

      def get_secret_key_id
        @secret_key_id
      end

      def get_session_token
        @session_token
      end

      def get_role_arn
        @role_arn
      end

      def get_role_session_name
        @role_session_name
      end

      def get_duration_sec
        @duration_sec
      end
    end

    class AwsMskIamConfig
      # this class is initialized upon startup and is responsible for managing credentials.
      # credential refreshes will lock this object to ensure that only 1 thread can update with
      # newly refreshed credentials. callers will receive a AwsMskIamCredential object
      # when requesting credentials.

      def initialize(aws_region:, access_key_id:, secret_key_id:, session_token: nil, 
        role_arn: nil, role_session_name: nil, duration_sec: 900)
        @semaphore = Mutex.new

        @aws_region = aws_region
        @access_key_id = access_key_id
        @secret_key_id = secret_key_id
        @session_token = session_token
        @role_arn = role_arn
        @role_session_name = role_session_name
        @duration_sec = duration_sec

        @refresh_after = Time.now.utc + (0.8 * @duration_sec)
      end

      def configured?
        sts_credentials_valid = true
        if @session_token.nil? && (!@role_arn.nil? || !@role_session_name.nil?)
          sts_credentials_valid = false
        elsif @role_arn.nil? && (!@session_token.nil? || !@role_session_name.nil?)
          sts_credentials_valid = false
        elsif @role_session_name.nil? && (!@session_token.nil? || !@role_arn.nil?)
          sts_credentials_valid = false
        end
        @aws_region && @access_key_id && @secret_key_id && sts_credentials_valid
      end

      def get_credentials
        @semaphore.lock
        aws_region = @aws_region
        access_key_id = @access_key_id
        secret_key_id = @secret_key_id

        if use_sts?
          session_token = @session_token
          role_arn = @role_arn
          role_session_name = @role_session_name
          duration_sec = @duration_sec

          @semaphore.unlock
          return AwsMskIamCredential.new(
            aws_region: aws_region, 
            access_key_id: access_key_id, 
            secret_key_id: secret_key_id, 
            session_token: session_token, 
            role_arn: role_arn, 
            role_session_name: role_session_name, 
            duration_sec: duration_sec
          )
        end

        @semaphore.unlock
        return AwsMskIamCredential.new(
          aws_region: aws_region, 
          access_key_id: access_key_id, 
          secret_key_id: secret_key_id
        )
      end

      def refresh_credentials(logger:)
        if perform_refresh?
          @semaphore.lock
          logger.debug "perform refresh at: #{Time.now}"
          @refresh_after = Time.now.utc + (0.8 * @duration_sec)
          @semaphore.unlock
        end

        logger.debug "thread tick at: #{Time.now}"
        return true
      end

      private

      def use_sts?
        !@role_arn.nil?
      end

      def perform_refresh?
        Time.now.utc >= @refresh_after
      end
    end

    class AwsMskIam
      AWS_MSK_IAM = "AWS_MSK_IAM"

      def initialize(aws_msk_iam_config:, logger:)
        @config = aws_msk_iam_config
        @logger = TaggedLogger.new(logger)

        Thread.new {
          # AWS enforces a minimum of 900 seconds between refreshes so it should be safe to check
          # for a potential refresh every 60 seconds. refreshes will occur when the token is 80%
          # expired (0.8 * duration_sec).
          while true
            if !@config.refresh_credentials(logger: @logger) 
              raise Kafka::Error, "SASL AWS_MSK_IAM token refresh failed"
            end
            sleep(60)
          end
        }
      end

      def ident
        AWS_MSK_IAM
      end

      def configured?
        @config.configured?
      end

      def authenticate!(host, encoder, decoder)
        credentials = @config.get_credentials
        @logger.debug "Authenticating #{credentials.get_access_key_id} with SASL #{AWS_MSK_IAM}"

        host_without_port = host.split(':', -1).first

        ymd = Time.now.utc.strftime("%Y%m%d")
        hms = Time.now.utc.strftime("%H%M%S")
        time_now = "#{ymd}T#{hms}Z"

        msg = authentication_payload(credentials: credentials, host: host_without_port, ymd: ymd, time_now: time_now)
        @logger.debug "Sending first client SASL AWS_MSK_IAM message:"
        @logger.debug msg
        encoder.write_bytes(msg)

        begin
          @server_first_message = decoder.bytes
          @logger.debug "Received first server SASL AWS_MSK_IAM message: #{@server_first_message}"

          raise Kafka::Error, "SASL AWS_MSK_IAM authentication failed: unknown error" unless @server_first_message
        rescue Errno::ETIMEDOUT, EOFError => e
          raise Kafka::Error, "SASL AWS_MSK_IAM authentication failed: #{e.message}"
        end

        @logger.debug "SASL #{AWS_MSK_IAM} authentication successful"
      end

      private

      def bin_to_hex(s)
        s.each_byte.map { |b| b.to_s(16).rjust(2, '0') }.join
      end

      def digest
        @digest ||= OpenSSL::Digest::SHA256.new
      end

      def authentication_payload(credentials:, host:, ymd:, time_now:)
        {
          'version': "2020_10_22",
          'host': host,
          'user-agent': "ruby-kafka",
          'action': "kafka-cluster:Connect",
          'x-amz-algorithm': "AWS4-HMAC-SHA256",
          'x-amz-credential': credentials.get_access_key_id + "/" + ymd + "/" + credentials.get_aws_region + "/kafka-cluster/aws4_request",
          'x-amz-date': time_now,
          'x-amz-signedheaders': "host",
          'x-amz-expires': "900",
          'x-amz-signature': signature(credentials: credentials, host: host, ymd: ymd, time_now: time_now)
        }.to_json
      end

      def canonical_request(credentials:, host:, ymd:, time_now:)
        "GET\n" +
        "/\n" +
        canonical_query_string(credentials: credentials, ymd: ymd, time_now: time_now) + "\n" +
        canonical_headers(host: host) + "\n" +
        signed_headers + "\n" +
        hashed_payload
      end

      def canonical_query_string(credentials:, ymd:, time_now:)
        URI.encode_www_form(
          "Action" => "kafka-cluster:Connect",
          "X-Amz-Algorithm" => "AWS4-HMAC-SHA256",
          "X-Amz-Credential" => credentials.get_access_key_id + "/" + ymd + "/" + credentials.get_aws_region + "/kafka-cluster/aws4_request",
          "X-Amz-Date" => time_now,
          "X-Amz-Expires" => "900",
          "X-Amz-SignedHeaders" => "host"
        )
      end

      def canonical_headers(host:)
        "host" + ":" + host + "\n"
      end

      def signed_headers
        "host"
      end

      def hashed_payload
        bin_to_hex(digest.digest(""))
      end

      def string_to_sign(credentials:, host:, ymd:, time_now:)
        "AWS4-HMAC-SHA256" + "\n" +
        time_now + "\n" +
        ymd + "/" + credentials.get_aws_region + "/kafka-cluster/aws4_request" + "\n" +
        bin_to_hex(digest.digest(canonical_request(credentials: credentials, host: host, ymd: ymd, time_now: time_now)))
      end

      def signature(credentials:, host:, ymd:, time_now:)
        date_key = OpenSSL::HMAC.digest("SHA256", "AWS4" + credentials.get_secret_key_id, ymd)
        date_region_key = OpenSSL::HMAC.digest("SHA256", date_key, credentials.get_aws_region)
        date_region_service_key = OpenSSL::HMAC.digest("SHA256", date_region_key, "kafka-cluster")
        signing_key = OpenSSL::HMAC.digest("SHA256", date_region_service_key, "aws4_request")
        signature = bin_to_hex(OpenSSL::HMAC.digest("SHA256", signing_key, string_to_sign(credentials: credentials, host: host, ymd: ymd, time_now: time_now)))

        signature
      end
    end
  end
end
