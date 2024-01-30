'use strict'
const env = process.env
const __envIn = 'dev';

let devEnvVariables = {
    NODEBB_SERVICE_URL: env.nodebb_service_url || 'https://dev.sunbirded.org', //'http://nodebb-service:4567/api',
    Authorization:  env.authorization_token || 'd8402b15-1d5f-4d84-9fae-595ef805f287', // '9c1adb65-14a9-421d-be75-6006f49c85b6',
    nodebb_api_slug: env.nodebb_api_slug || '/discussions/api',
    sunbird_learner_service_host: 'http://learner-service:9000/',
    lms_user_read_path: 'private/user/v1/read/',
    CASSANDRA_IP: env.CASSANDRA_IP || '10.177.157.30',
    CASSANDRA_KEYSPACE: env.CASSANDRA_KEYSPACE || 'xyz',
    CASSANDRA_PASSWORD: env.CASSANDRA_PASSWORD || '',
    CASSANDRA_USERNAME: env.CASSANDRA_USERNAME || '',
}

module.exports = devEnvVariables;