<#assign sec=JspTaglibs["http://www.springframework.org/security/tags"] />
<#include "/fragments/header.ftlh">
<#-- ${account.iban} is not shown here -->
<h1>${account.holder!"?"}</h1>
<#assign primary = account.cards[0]>
<p>Expires ${primary.expiry}</p>
<@sec.authorize access="hasRole('TELLER')">
  <p>${account.iban}</p>
  <#list account.cards as card>
    <li>${card.number}</li>
  </#list>
</@sec.authorize>
