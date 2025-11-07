from sqlalchemy import Column, String, Integer, Text, ARRAY
from app.database import Base

class RemediationTemplate(Base):
    __tablename__ = "remediation_templates"

    id = Column(Integer, primary_key=True, autoincrement=True)
    vulnerability_type = Column(String(100))
    cwe_id = Column(String(20))
    title = Column(String(255))
    description = Column(Text)
    remediation_steps = Column(Text)
    code_examples = Column(Text)
    effort_hours = Column(Integer)
    required_skills = Column(ARRAY(Text))
    references = Column(ARRAY(Text))