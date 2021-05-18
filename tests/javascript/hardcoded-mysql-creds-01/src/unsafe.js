var mysql = require("mysql");

mysql.createConnection({
    host: "localhost",
    user: "root",
    password: "root",
    database: "ultra_mega_top_secret"
});

var mysql2 = require("mysql2");

mysql2.createConnection({
    host: "localhost",
    user: "root",
    password: "root",
    database: "nsa_database"
});