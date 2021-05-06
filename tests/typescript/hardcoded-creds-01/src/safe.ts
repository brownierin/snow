import mysql = require('mysql');

function getconfig() {
    
}

export default class MyObjects {
    constructor() {
        let config = getconfig();
        let connection = mysql.createConnection({
            host: config.hostname,
            user: config.user,
            password: config.password,
            database: config.database
        });
    }
}