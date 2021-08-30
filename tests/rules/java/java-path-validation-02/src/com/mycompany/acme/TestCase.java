package com.mycompany.test;

public class Test extends HttpServlet {
    // unsafe
    public void doGet(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
      String serverName = request.getServerName();

      if (serverName.equals("localhost")) {
          // ... do something
      }

      String serverName2 = request.getHeader("Host");

      if (serverName2.equals("localhost")) {
          // ... do something
      }

      if (request.getHeader("Host").equals("localhost")) {
          // ... do something
      }
   }
}
