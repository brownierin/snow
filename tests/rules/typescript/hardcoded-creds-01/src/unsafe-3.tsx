import { createConnection } from "mysql";

export default class MyObjects {
    constructor(){
        let connection = createConnection({
            host: 'localhost',
            user: 'root',
            password: 'root',
            database: 'answers-to-life-and-universe'
        });    
    }
}