# frozen_string_literal: true

# Will only work with IAM enabled MSK clusters on AWS.

$LOAD_PATH.unshift(File.expand_path("../../lib", __FILE__))

require "kafka"

logger = Logger.new($stderr)
brokers = ENV.fetch("BOOTSTRAP_BROKERS")
brokers = brokers.split(",")
access_key_id = ENV.fetch("AWS_ACCESS_KEY_ID")
secret_access_key = ENV.fetch("AWS_SECRET_ACCESS_KEY")
# session_token = ENV.fetch("AWS_SESSION_TOKEN")

topic = "test-topic"

kafka = Kafka.new(
    brokers,
    client_id: "sasl-aws-msk-iam-producer",
    logger: logger,
    ssl_ca_certs_from_system: true,
    sasl_aws_msk_iam_access_key_id: access_key_id,
    sasl_aws_msk_iam_secret_key_id: secret_access_key,
    # sasl_aws_msk_iam_session_token: session_token,
    sasl_aws_msk_iam_aws_region: "us-east-1",
)

producer = kafka.producer

begin
    for i in 1..10 do
        producer.produce("test-ruby-#{i}", topic: topic)
        producer.deliver_messages
        sleep(30)
    end
ensure
    producer.shutdown
end
