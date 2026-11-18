<%@ taglib prefix="sec" uri="http://www.springframework.org/security/tags" %>
<html>
<body>
<p>${contact.name}</p>
<sec:authorize url="/admin/contacts" method="DELETE">
  <p>${contact.email}</p>
</sec:authorize>
<sec:accesscontrollist hasPermission="ADMINISTRATION" domainObject="${contact}">
  <p>${contact.phone}</p>
</sec:accesscontrollist>
<sec:authorize url="/admin/users/${contact.id}">
  <p>${contact.notes}</p>
</sec:authorize>
</body>
</html>
