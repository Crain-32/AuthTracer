<%@ taglib prefix="sec" uri="http://www.springframework.org/security/tags" %>
<html>
<body>
<h1>${member.name}</h1>
<sec:authorize access="hasRole('ADMIN')">
  <p>${member.email}</p>
</sec:authorize>
</body>
</html>
