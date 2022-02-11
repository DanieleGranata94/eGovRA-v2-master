from django.db import models
from django.core.validators import FileExtensionValidator

# Create your models here.

class System(models.Model):
    name = models.CharField(max_length=100)

    class Meta:
        verbose_name="System"
        verbose_name_plural="Systems"

    def __str__(self):
        return self.name

    def delete(self, *args, **kwargs):
        processes = Process.objects.filter(system=self)
        for process in processes:
            process.xml.delete()
        super().delete(*args, **kwargs)

class Process(models.Model):
    name = models.CharField(max_length=100)
    xml = models.FileField(upload_to='processes/xml/',
                           validators=[FileExtensionValidator(allowed_extensions=['xml','bpmn'])])
    system = models.ForeignKey(System, on_delete=models.CASCADE)

    class Meta:
        verbose_name="Process"
        verbose_name_plural="Processes"

    def __str__(self):
        return self.name

    def delete(self, *args, **kwargs):
        self.xml.delete()
        super().delete(*args, **kwargs)

class Asset_type(models.Model):
    name = models.CharField(max_length=100)
    description = models.CharField(max_length=500)

    class Meta:
        verbose_name="Asset_type"
        verbose_name_plural="Assets_types"

    def __str__(self):
        return self.name

class Asset(models.Model):
    name = models.CharField(max_length=100)
    bpmn_id= models.CharField(max_length=100,null=True)
    process = models.ForeignKey(Process, on_delete=models.CASCADE)
    asset_type = models.ForeignKey(Asset_type,on_delete=models.CASCADE,null=True)
    position=models.CharField(max_length=100,null=True)

    class Meta:
        verbose_name="Asset"
        verbose_name_plural="Assets"

    def __str__(self):
        return self.name

class Attribute_value(models.Model):
    value = models.CharField(max_length=100)

    class Meta:
        verbose_name="Attribute_value"
        verbose_name_plural="Attributes_values"

    def __str__(self):
        return self.value

class Threat(models.Model):
    name = models.CharField(max_length=100)
    description = models.CharField(max_length=500)

    class Meta:
        verbose_name="Threat"
        verbose_name_plural="Threats"

    def __str__(self):
        return self.name

class Attribute(models.Model):
    attribute_name = models.CharField(max_length=100)
    asset_type = models.ForeignKey(Asset_type,on_delete=models.CASCADE)
    attribute_value = models.ForeignKey(Attribute_value,on_delete=models.CASCADE)

    class Meta:
        verbose_name="Attribute"
        verbose_name_plural="Attributes"

    def __str__(self):
        return self.attribute_name

class Control(models.Model):
    name = models.CharField(max_length=100)
    description = models.CharField(max_length=500)

    class Meta:
        verbose_name="Control"
        verbose_name_plural="Controls"

    def __str__(self):
        return self.name

class Asset_has_attribute(models.Model):
    asset = models.ForeignKey(Asset,on_delete=models.CASCADE)
    attribute = models.ForeignKey(Attribute,on_delete=models.CASCADE)

class Threat_has_attribute(models.Model):
    threat = models.ForeignKey(Threat,on_delete=models.CASCADE)
    attribute = models.ForeignKey(Attribute,on_delete=models.CASCADE)

class Threat_has_control(models.Model):
    threat = models.ForeignKey(Threat, on_delete=models.CASCADE)
    control = models.ForeignKey(Control, on_delete=models.CASCADE)

# AL MODELLO DEI DATI MANCA SOLO LA PARTE RELATIVA AI THREAT AGENTS


class ThreatAgentCategory(models.Model):
    category = models.CharField(max_length=100,null=True)
    description = models.CharField(max_length=500,null=True)
    common_actions = models.CharField(max_length=500,null=True)

class ThreatAgentAttribute(models.Model):
    attribute = models.CharField(max_length=100,null=True)
    attribute_value = models.CharField(max_length=100,null=True)
    description = models.CharField(max_length=500,null=True)
    score = models.IntegerField(null=True)

class ThreatAgentQuestion(models.Model):
    Qid = models.CharField(max_length=500, null=True)
    question = models.CharField(max_length=500)

class Reply(models.Model):
    reply = models.CharField(max_length=500)
    multiple = models.BooleanField(default=False)

class TAReplies_Question(models.Model):
    reply = models.ForeignKey(Reply, on_delete=models.CASCADE,null=True)
    question = models.ForeignKey(ThreatAgentQuestion, on_delete=models.CASCADE,null=True)

class TACategoryAttribute(models.Model):
    category = models.ForeignKey(ThreatAgentCategory, on_delete=models.CASCADE, null=True)
    attribute = models.ForeignKey(ThreatAgentAttribute, on_delete=models.CASCADE, null=True)

class TAReplyCategory(models.Model):
    reply = models.ForeignKey(Reply, on_delete=models.CASCADE, null=True)
    category = models.ForeignKey(ThreatAgentCategory, on_delete=models.CASCADE, null=True)

class ThreatAgentRiskScores(models.Model):
    system = models.ForeignKey(System, on_delete=models.CASCADE)
    skill = models.IntegerField()
    size = models.IntegerField()
    motive = models.IntegerField()
    opportunity = models.IntegerField()
    created_at = models.DateTimeField(auto_now_add=True, null=True)
    updated_at = models.DateTimeField(auto_now=True, null=True)

class System_ThreatAgent(models.Model):
    system = models.ForeignKey(System, on_delete=models.CASCADE)
    category = models.ForeignKey(ThreatAgentCategory, on_delete=models.CASCADE, null=True)

class Risk(models.Model):
    system = models.ForeignKey(System, on_delete=models.CASCADE)
    asset = models.ForeignKey(Asset, on_delete=models.CASCADE, null=True)
    threat = models.ForeignKey(Threat, on_delete=models.CASCADE)

    #Threat Agents
    skill= models.IntegerField(null=True)
    motive= models.IntegerField(null=True)
    opportunity= models.IntegerField(null=True)
    size= models.IntegerField(null=True)

    #vulnerability factors
    ease_of_discovery = models.IntegerField(null=True)
    ease_of_exploit = models.IntegerField(null=True)
    intrusion_detection = models.IntegerField(null=True)
    awareness = models.IntegerField(null=True)

    #technical impact factors
    loss_of_confidentiality = models.IntegerField(null=True)
    loss_of_integrity = models.IntegerField(null=True)
    loss_of_availability = models.IntegerField(null=True)
    loss_of_accountability = models.IntegerField(null=True)

    #business impact factors
    financial = models.IntegerField(null=True)
    reputation = models.IntegerField(null=True)
    non_compliance = models.IntegerField(null=True)
    privacy = models.IntegerField(null=True)
