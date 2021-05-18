import * as mysql from "mysql2";

export default class MyObjects {
    constructor(){
        let connection = mysql.createConnection({
            host: 'localhost',
            user: 'root',
            password: 'root',
            database: 'answers-to-life-and-universe'
        });    
    }
}