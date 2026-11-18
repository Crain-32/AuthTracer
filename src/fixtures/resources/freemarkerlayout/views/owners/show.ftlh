<#import "/spring.ftl" as spring/>
<#import "/layout/page.ftlh" as layout/>
<#assign sec=JspTaglibs["http://www.springframework.org/security/tags"]/>
<#assign title>Owner ${owner.lastName}</#assign>
<@layout.page title=title>
  <h2><@spring.message "owner.details"/></h2>
  <@spring.bind "owner.telephone"/>
  <@sec.authorize url="/owners/notes">
    <p>${owner.notes}</p>
  </@sec.authorize>
  <#attempt>
    <@sec.authorize access="hasRole('VET')">
      <#list owner.visits as visit>
        <p>${visit.date}: ${visit.diagnosis}</p>
      </#list>
    </@sec.authorize>
  <#recover>
    <p>No visits</p>
  </#attempt>
</@layout.page>
