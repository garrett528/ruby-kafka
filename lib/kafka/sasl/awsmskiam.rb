# frozen_string_literal: true

require 'aws-sigv4'

module Kafka
    module Sasl
        class AwsMskIam
            AWS_MSK_IAM_IDENT = "AWS_MSK_IAM"

            def initialize(access_key_id:, secret_access_key:, aws_region:, logger:)
                @semaphore = Mutex.new

                @access_key_id = access_key_id
                @secret_access_key = secret_access_key
                @aws_region = aws_region
                
                if configured?
                    get_signer
                end
            end

            def ident
                AWS_MSK_IAM_IDENT
            end

            def configured?
                @access_key_id && @secret_access_key && @aws_region
            end

            def authenticate!(host, encoder, decoder)
                @logger.debug "Authenticating to #{host} with SASL #{AWS_MSK_IAM}"

                host_without_port = host.split(':', -1).first

                signer = get_signer
                signature = signer.sign_request(
                    http_method: 'GET',
                    url: host_without_port,
                    headers: {
                      'Host' => 'host',
                    }
                )

                signature.headers['x-amz-credential']
                signature.headers['x-amz-date']
                signature.headers['x-amz-security-token']
                signature.headers['x-amz-signedheaders']
                signature.headers['x-amz-expires']

                @logger.debug "Canonical request: #{signature.canonical_request}"
                @logger.debug "String to sign: #{signature.string_to_sign}"
                @logger.debug "Content SHA256: #{signature.content_sha256}"

                msg = authentication_payload(signature: signature.content_sha256)
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

            def get_signer
                @signer = Aws::Sigv4::Signer.new(
                    service: 'kafka-cluster',
                    region: @aws_region,
                    # static credentials
                    access_key_id: @access_key_id,
                    secret_access_key: @secret_access_key
                )
            end

            def authentication_payload(signature:)
                now = Time.now
                {
                  'version': "2020_10_22",
                  'host': host,
                  'user-agent': "ruby-kafka",
                  'action': "kafka-cluster:Connect",
                  'x-amz-algorithm': "AWS4-HMAC-SHA256",
                  'x-amz-credential': @access_key_id + "/" + now.strftime("%Y%m%d") + "/" + @aws_region + "/kafka-cluster/aws4_request",
                  'x-amz-date': now.strftime("%Y%m%dT%H%M%SZ"),
                  'x-amz-signedheaders': "host",
                  'x-amz-expires': "900",
                  'x-amz-signature': signature
                }.to_json
              end
        end
    end
end
