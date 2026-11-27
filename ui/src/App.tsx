import React from 'react';
import { Routes, Route, Navigate } from 'react-router-dom';
import { Layout } from './components/Layout';
import { CampaignListScreen } from './screens/CampaignListScreen';
import { CampaignCreateScreen } from './screens/CampaignCreateScreen';
import { CampaignDetailScreen } from './screens/CampaignDetailScreen';
import { JobTableFlowScreen } from './screens/JobTableFlowScreen';
import { AssetGraphScreen } from './screens/AssetGraphScreen';
import { ToolCatalogueScreen } from './screens/ToolCatalogueScreen';
import { ActivityScreen } from './screens/ActivityScreen';

export const App: React.FC = () => {
  return (
    <Routes>
      <Route path="/" element={<Layout />}>
        <Route index element={<Navigate to="/campaigns" replace />} />
        <Route path="campaigns" element={<CampaignListScreen />} />
        <Route path="campaigns/new" element={<CampaignCreateScreen />} />
        <Route path="campaigns/:id" element={<CampaignDetailScreen />} />
        <Route path="jobs" element={<JobTableFlowScreen />} />
        <Route path="activity" element={<ActivityScreen />} />
        <Route path="assets" element={<AssetGraphScreen />} />
        <Route path="tools" element={<ToolCatalogueScreen />} />
        <Route path="*" element={<Navigate to="/campaigns" replace />} />
      </Route>
    </Routes>
  );
};
