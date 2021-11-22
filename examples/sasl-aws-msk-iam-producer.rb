# frozen_string_literal: true

# Will only work with IAM enabled MSK clusters on AWS.

$LOAD_PATH.unshift(File.expand_path("../../lib", __FILE__))

require "kafka"

logger = Logger.new($stderr)
brokers = 'localhost:9092'

topic = "test-topic"

kafka = Kafka.new(
    seed_brokers: brokers,
    client_id: "sasl-aws-msk-iam-producer.rb",
    logger: logger,
    sasl_over_ssl: false,
    sasl_aws_msk_iam_access_key_id: "keyId",
    sasl_aws_msk_iam_secret_access_key: "access_key",
    sasl_aws_msk_iam_region: "us-east-1",
)

producer = kafka.producer

begin
    producer.produce("test", topic: topic)
    producer.deliver_messages
ensure
    producer.shutdown
end