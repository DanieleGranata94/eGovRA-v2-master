"""eGov_RA URL Configuration

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/3.1/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""
from django.contrib import admin
from django.urls import path
from django.conf import settings
from django.conf.urls.static import static

from parsingbpmn import views
from parsingbpmn.views import bpmn_process_management, system_management, \
    delete_process, delete_system, process_enrichment, threat_modeling, process_view_task_type, process_view_attribute, \
    task_type_enrichment, export_threat_modeling, threats_and_controls, bpmn_viewer, edit_process, \
    from_ta_to_system_management, threat_modeling_view

urlpatterns = [
    path('admin/', admin.site.urls),
    path('', system_management, name='system_management'),
    path('bpmn_process_management/<int:systemId>', bpmn_process_management, name='bpmn_process_management'),
    path('process_view_task_type/<int:systemId>/<int:processId>', process_view_task_type, name='process_view_task_type'),
    path('process_view_attribute/<int:systemId>/<int:processId>', process_view_attribute, name='process_view_attribute'),
    path('edit_process/<int:systemId>/<int:processId>', edit_process, name='edit_process'),
    path('delete_process/<int:systemId>/<int:processId>', delete_process, name='delete_process'),
    path('delete_system/<int:systemId>', delete_system, name='delete_system'),
    path('process_enrichment/<int:systemId>/<int:processId>', process_enrichment, name='process_enrichment'),
    path('bpmn_viewer/<int:pk>', bpmn_viewer, name='bpmn_viewer'),
    path('task_type_enrichment/<int:systemId>/<int:processId>', task_type_enrichment, name='task_type_enrichment'),
    path('threats_and_controls/<int:systemId>/<int:processId>', threats_and_controls, name='threats_and_controls'),
    path('threat_modeling_view/<int:systemId>/<int:processId>', threat_modeling_view, name='threat_modeling_view'),
    path('export_threat_modeling/<int:systemId>/<int:processId>', export_threat_modeling, name='export_threat_modeling'),
    path('threat_agent_wizard/<int:systemId>/<int:processId>/<int:assetId>', views.threat_agent_wizard, name='threat_agent_wizard'),
    path('threat_agent_generation/<int:systemId>/<int:processId>/<int:assetId>', views.threat_agent_generation, name='threat_agent_generation'),
    path('calculate_threat_agent_risks/<int:systemId>/<int:processId>/<int:assetId>', views.calculate_threat_agent_risks, name='calculate_threat_agent_risks'),
    path('stride_impact_evaluation/<int:systemId>/<int:processId>/<int:assetId>', views.stride_impact_evaluation, name='stride_impact_evaluation'),
    path('risk_analysis/<int:systemId>/<int:processId>/<int:assetId>', views.risk_analysis, name='risk_analysis'),

]

if settings.DEBUG:
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)