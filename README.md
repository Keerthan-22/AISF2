# AISF Security Platform

This repository contains the AISF (AI Security Framework) platform code.

## Project Structure

- `backend/`: Contains the Python backend server and ML models
- `frontend/`: Contains the React.js frontend application

## Important Note About Datasets

Due to GitHub's file size limitations, the following datasets are not included in this repository:

- `backend/app/ml_models/datasets/`: Contains various security datasets
  - CICIDS2017
  - NSL-KDD
  - Synthetic data
  - ToN-IoT
  - UNSW-NB15

Please contact the repository maintainers for access to these datasets or download them from their respective sources:

1. CICIDS2017: https://www.unb.ca/cic/datasets/ids-2017.html
2. NSL-KDD: https://www.unb.ca/cic/datasets/nsl.html
3. UNSW-NB15: https://research.unsw.edu.au/projects/unsw-nb15-dataset

After obtaining the datasets, place them in the appropriate directories under `backend/app/ml_models/datasets/`.