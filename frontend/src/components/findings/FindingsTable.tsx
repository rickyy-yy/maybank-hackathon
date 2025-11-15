const [jiraModalData, setJiraModalData] = useState<{ findingIds: string[]; titles: string[] } | null>(null);

const handleCreateJiraTickets = (findingIds: string[]) => {
  console.log('🎯 Opening Jira modal for findings:', findingIds);
  const titles = findingIds.map(id => {
    const finding = findings.find(f => f.id === id);
    return finding ? finding.title : 'Unknown';
  });
  setJiraModalData({ findingIds, titles });
};

// In the JSX, make sure the modal is rendered:
{jiraModalData && (
  <JiraTicketModal
    findingIds={jiraModalData.findingIds}
    findingTitles={jiraModalData.titles}
    onClose={() => setJiraModalData(null)}
    onSuccess={() => {
      setJiraModalData(null);
      window.location.reload();
    }}
  />
)}

// And the button should call handleCreateJiraTickets:
<button
  onClick={() => handleCreateJiraTickets([finding.id])}
  className="px-4 py-2 bg-gray-600 text-white rounded-md hover:bg-gray-700 font-medium text-sm"
>
  Create Jira Ticket
</button>