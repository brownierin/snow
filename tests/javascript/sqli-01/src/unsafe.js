var query = "SELECT * FROM mytable WHERE abc = '" + value + "'";
doQuery(query);

var query2 = "SeLeCt * FROM mytable WHERE ";
query2 += "abc ='" + value + "'";
doQuery(query2);