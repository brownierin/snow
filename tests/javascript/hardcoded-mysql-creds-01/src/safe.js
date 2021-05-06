var mysql = require("mysql");
var config = getConfig();

mysql.createConnection({
    host: config.host,
    user: config.user,
    password: config.password,
    database: config.database
});

var mysql2 = require("mysql2");

mysql2.createConnection({
    host: config.host,
    user: config.user,
    password: config.password,
    database: config.database
});