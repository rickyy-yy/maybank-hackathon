const handleSubmit = async () => {
  console.log('🎫 Creating Jira tickets for:', findingIds);
  setIsSubmitting(true);
  setError(null);

  try {
    const API_URL = import.meta.env.VITE_API_URL || 'http://localhost:8000';
    const url = `${API_URL}/api/v1/integrations/jira/create-tickets`;
    
    const payload = {
      finding_ids: findingIds,
      project_key: formData.projectKey,
      issue_type: formData.issueType,
      priority: formData.priority,
      assignee: formData.assignee || null,
      labels: formData.labels.split(',').map(l => l.trim()).filter(Boolean),
      additional_description: formData.description,
    };
    
    console.log('📤 Sending request to:', url);
    console.log('📦 Payload:', payload);
    
    const response = await fetch(url, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify(payload),
    });

    console.log('📥 Response status:', response.status);
    const data = await response.json();
    console.log('📥 Response data:', data);

    if (!response.ok) {
      throw new Error(data.detail || 'Failed to create Jira tickets');
    }

    setCreatedTickets(data.tickets || []);
    setSuccess(true);
    
    setTimeout(() => {
      onSuccess();
    }, 2000);

  } catch (err) {
    console.error('❌ Error creating tickets:', err);
    setError(err instanceof Error ? err.message : 'An error occurred');
  } finally {
    setIsSubmitting(false);
  }
};