package com.mycompany.test;

public class Test extends HttpServlet {
    public void doGet(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
      String requestURI = request.getRequestURI();

      if (requestURI.contains("yay")) {
          // ... do something
      }
   }
}