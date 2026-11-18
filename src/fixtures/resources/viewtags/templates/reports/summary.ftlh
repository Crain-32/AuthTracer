<#assign sec=JspTaglibs["http://www.springframework.org/security/tags"]>
<html>
<body>
<p>${report.title}</p>
<@sec.authorize url="/admin/reports">
<p>${report.headcount}</p>
</@sec.authorize>
<@sec.accesscontrollist hasPermission="READ" domainObject=report>
<p>${report.notes}</p>
</@sec.accesscontrollist>
</body>
</html>
