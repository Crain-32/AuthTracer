<%@ include file="/WEB-INF/jsp/include.jsp" %>
<html>
<body>
<table>
<c:forEach var="contact" items="${contacts}">
  <tr>
    <td><c:out value="${contact.name}"/></td>
    <td>${contact.email}</td>
    <security:authorize access="hasRole('SUPERVISOR')">
      <td><c:out value="${contact.phone}"/></td>
    </security:authorize>
  </tr>
</c:forEach>
</table>
</body>
</html>
