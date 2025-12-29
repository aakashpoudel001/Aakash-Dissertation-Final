import React, { useState, useEffect } from 'react';
import background from './assets/flowar.jpeg';


// Main App Component
function App() {
  const [currentPage, setCurrentPage] = useState('login'); // Controls which page is displayed
  const [isAuthenticated, setIsAuthenticated] = useState(false); // Authentication state
  const [predictionResult, setPredictionResult] = useState(null); // Stores current prediction result
  const [uploadedImage, setUploadedImage] = useState(null); // Stores the uploaded image for preview
  const [authToken, setAuthToken] = useState(localStorage.getItem('authToken') || null); // Store auth token
  const [username, setUsername] = useState(localStorage.getItem('username') || null); // Store username - CORRECTED LINE

  // Check authentication status on component mount
  useEffect(() => {
    if (authToken) {
      setIsAuthenticated(true);
      setCurrentPage('upload'); // Redirect to upload page if already authenticated
    }
  }, [authToken]);

  // Base URL for your Django API
  const API_BASE_URL = 'http://localhost:8000/api'; // IMPORTANT: Change this in production!

  // --- Authentication Handlers ---
  const handleLogin = async (username, password) => {
    try {
      const response = await fetch(`${API_BASE_URL}/login/`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ username, password }),
      });
      const data = await response.json();

      if (response.ok) {
        localStorage.setItem('authToken', data.token);
        localStorage.setItem('username', data.username);
        setAuthToken(data.token);
        setUsername(data.username);
        setIsAuthenticated(true);
        setCurrentPage('upload');
        return true;
      } else {
        alert(`Login failed: ${data.error || 'Unknown error'}`);
        return false;
      }
    } catch (error) {
      console.error('Error during login:', error);
      alert('An error occurred during login. Please try again.');
      return false;
    }
  };

  const handleRegister = async (username, email, password) => {
    try {
      const response = await fetch(`${API_BASE_URL}/register/`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ username, email, password }),
      });
      const data = await response.json();

      if (response.ok) {
        alert(data.message);
        setCurrentPage('login');
      } else {
        alert(`Registration failed: ${data.error || 'Unknown error'}`);
      }
    } catch (error) {
      console.error('Error during registration:', error);
      alert('An error occurred during registration. Please try again.');
    }
  };

  const handleForgotPassword = async (email) => {
    try {
      const response = await fetch(`${API_BASE_URL}/forgot-password/`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ email }),
      });
      const data = await response.json();
      alert(data.message);
      setCurrentPage('login');
    } catch (error) {
      console.error('Error during forgot password request:', error);
      alert('An error occurred. Please try again.');
    }
  };

  const handleResetPassword = async (uidb64, token, new_password) => {
    // Trim any potential whitespace or unwanted slashes from the ends
    const cleanedUidb64 = uidb64.trim().replace(/\/$/, '');
    const cleanedToken = token.trim().replace(/\/$/, '');

    console.log("DEBUG - Cleaned UID before fetch:", cleanedUidb64);
    console.log("DEBUG - Cleaned Token before fetch:", cleanedToken);

    try {
      const response = await fetch(`${API_BASE_URL}/reset-password/${cleanedUidb64}/${cleanedToken}/`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ new_password }),
      });
      const data = await response.json();
      if (response.ok) {
        alert(data.message);
        setCurrentPage('login');
      } else {
        alert(`Password reset failed: ${data.error || 'Unknown error'}`);
      }
    } catch (error) {
      console.error('Error during password reset:', error);
      alert('An error occurred. Please try again.');
    }
  };

  const handleLogout = async () => {
    try {
      const response = await fetch(`${API_BASE_URL}/logout/`, {
        method: 'POST',
        headers: {
          'Authorization': `Token ${authToken}`,
        },
      });
      const data = await response.json();
      if (response.ok) {
        localStorage.removeItem('authToken');
        localStorage.removeItem('username');
        setAuthToken(null);
        setUsername(null);
        setIsAuthenticated(false);
        setCurrentPage('login');
        setPredictionResult(null);
        setUploadedImage(null);
        alert(data.message);
      } else {
        alert(`Logout failed: ${data.error || 'Unknown error'}`);
      }
    } catch (error) {
      console.error('Error during logout:', error);
      alert('An error occurred during logout. Please try again.');
    }
  };

  // --- Image Prediction Handler ---
  const handleImageUpload = async (file) => {
    if (!file) {
      alert('Please select an image to upload.');
      return;
    }

    setUploadedImage(URL.createObjectURL(file)); // Create a preview URL

    const formData = new FormData();
    formData.append('image', file);

    try {
      const response = await fetch(`${API_BASE_URL}/predict/`, {
        method: 'POST',
        headers: {
          'Authorization': `Token ${authToken}`, // Send the authentication token
        },
        body: formData,
      });
      const data = await response.json();
      if (response.ok) {
        setPredictionResult(data.prediction);
        setCurrentPage('result');
      } else {
        alert(`Prediction failed: ${data.error || 'Unknown error'}`);
        setPredictionResult(null); // Clear prediction on failure
      }
    } catch (error) {
      console.error('Error during prediction:', error);
      alert('An error occurred during prediction. Please try again.');
      setPredictionResult(null); // Clear prediction on error
    }
  };

  // --- Conditional Page Rendering Logic ---
  const renderPage = () => {
    // Check URL for password reset parameters (for direct link access)
    const path = window.location.pathname;
    if (path.startsWith('/reset-password/')) {
      // Split the path and filter out any empty strings that result from leading/trailing slashes
      const parts = path.split('/').filter(part => part !== '');

      // Now, for a URL like /reset-password/uidb64_value/token_value/, parts will be:
      // ['reset-password', 'uidb64_value', 'token_value']
      // So, uidb64 is at index 1 and token is at index 2 of the filtered array.
      const uidb64 = parts[1];
      const token = parts[2];

      // Added for debugging - check your browser console after this change!
      console.log("DEBUG - Parsed UIDb64 from URL:", uidb64);
      console.log("DEBUG - Parsed Token from URL:", token);

      if (uidb64 && token) { // Ensure both parts are present
        // Pass onResetPassword and onNavigate directly
        return <ResetPasswordConfirmPage uidb64={uidb64} token={token} onResetPassword={handleResetPassword} onNavigate={setCurrentPage} />;
      } else {
        // Handle malformed URL case, e.g., redirect to login or show error
        alert("Invalid password reset link. Please try again from 'Forgot Password'.");
        window.history.pushState({}, '', '/login'); // Clean up the URL
        return <LoginPage onLogin={handleLogin} onNavigate={setCurrentPage} />;
      }
    }

    switch (currentPage) {
      case 'login':
        return <LoginPage onLogin={handleLogin} onNavigate={setCurrentPage} />;
      case 'register':
        return <RegisterPage onRegister={handleRegister} onNavigate={setCurrentPage} />;
      case 'forgot-password':
        return <ForgotPasswordPage onForgotPassword={handleForgotPassword} onNavigate={setCurrentPage} />;
      case 'upload':
        return isAuthenticated ? (
          <ImageUploadPage onImageUpload={handleImageUpload} />
        ) : (
          <LoginPage onLogin={handleLogin} onNavigate={setCurrentPage} />
        );
      case 'result':
        return isAuthenticated ? (
          <PredictionResultPage
            prediction={predictionResult}
            imagePreview={uploadedImage}
            onNavigate={setCurrentPage}
          />
        ) : (
          <LoginPage onLogin={handleLogin} onNavigate={setCurrentPage} />
        );
      case 'history':
        return isAuthenticated ? (
          <ResultsHistoryPage authToken={authToken} API_BASE_URL={API_BASE_URL} />
        ) : (
          <LoginPage onLogin={handleLogin} onNavigate={setCurrentPage} />
        );
      default:
        return <LoginPage onLogin={handleLogin} onNavigate={setCurrentPage} />;
    }
  };

  return (
    // Main container with floral background
    <div
      className="min-h-screen flex flex-col font-sans bg-cover bg-center"
      style={{ backgroundImage: `url(${background})` }}
    >
      {/* Navigation Bar (only shown when authenticated) */}
      {isAuthenticated && (
        <NavBar
          username={username}
          onLogout={handleLogout}
          onNavigate={setCurrentPage}
          hasPrediction={predictionResult !== null} // Pass if there's a prediction to show 'Current Result' link
          currentPage={currentPage} // Pass current page to highlight active link
        />
      )}
      {/* Main content area, grows to fill remaining space */}
      <div className="flex-grow flex items-center justify-center p-4">
        {renderPage()}
      </div>
    </div>
  );
}

// --- Navigation Bar Component ---
const NavBar = ({ username, onLogout, onNavigate, hasPrediction, currentPage }) => {
  // Helper function to apply active/inactive styles to navigation links
  const navLinkClasses = (pageName) =>
    `font-medium transition duration-200 px-3 py-2 rounded-md ${
      currentPage === pageName
        ? 'bg-indigo-100 text-indigo-700' // Active link style
        : 'text-gray-600 hover:text-indigo-600' // Inactive link style with subtle hover
    }`;

  return (
    <nav className="bg-white shadow-md p-4 sticky top-0 z-50">
      <div className="container mx-auto flex justify-between items-center">
        {/* Left Section: App Title & Navigation Links */}
        <div className="flex items-center">
          <h1 className="text-2xl font-bold text-indigo-700 mr-8">Image Predictor</h1>
          <div className="hidden md:flex space-x-2"> {/* Links shown on medium screens and up */}
            <button
              onClick={() => onNavigate('upload')}
              className={navLinkClasses('upload')}
            >
              Upload
            </button>
            {hasPrediction && ( // "Current Result" link only appears if a prediction exists
              <button
                onClick={() => onNavigate('result')}
                className={navLinkClasses('result')}
              >
                Current Result
              </button>
            )}
            <button
              onClick={() => onNavigate('history')}
              className={navLinkClasses('history')}
            >
              Results History
            </button>
          </div>
        </div>

        {/* Right Section: User Info & Logout Button */}
        <div className="flex items-center space-x-4">
          {username && (
            <span className="text-gray-700 font-medium hidden sm:block"> {/* "Hello, User!" hidden on extra-small screens */}
              Hello, <span className="text-indigo-600 font-semibold">{username}</span>!
            </span>
          )}
          <Button onClick={onLogout} className="!w-auto !py-2 !px-4 text-sm"> {/* Custom size for nav bar button */}
            Logout
          </Button>
        </div>
      </div>
    </nav>
  );
};

// --- Reusable UI Components (No Hover Animations) ---
// Reusable Card Component for consistent styling
const Card = ({ children, title }) => (
  <div className="bg-white p-8 rounded-xl shadow-2xl w-full max-w-md border border-gray-100">
    {title && <h2 className="text-4xl font-extrabold text-gray-800 mb-8 text-center tracking-tight">{title}</h2>}
    {children}
  </div>
);

// Input Field Component
const InputField = ({ id, label, type, value, onChange, placeholder }) => (
  <div className="mb-6">
    <label htmlFor={id} className="block text-gray-700 text-sm font-semibold mb-2">
      {label}
    </label>
    <input
      type={type}
      id={id}
      className="shadow-sm appearance-none border border-gray-300 rounded-lg w-full py-3 px-4 text-gray-700 leading-tight focus:outline-none focus:ring-3 focus:ring-indigo-300 focus:border-indigo-500 transition duration-300 ease-in-out"
      placeholder={placeholder}
      value={value}
      onChange={onChange}
      required
    />
  </div>
);

// Button Component (with subtle background hover for feedback)
const Button = ({ onClick, children, className = '', disabled = false, type = 'button' }) => (
  <button
    type={type}
    onClick={onClick}
    className={`w-full bg-indigo-600 hover:bg-indigo-700 text-white font-bold py-3 px-4 rounded-lg focus:outline-none focus:ring-3 focus:ring-indigo-400 focus:ring-opacity-75 transition duration-300 shadow-lg ${className} ${disabled ? 'opacity-50 cursor-not-allowed' : ''}`}
    disabled={disabled}
  >
    {children}
  </button>
);

// Navigation Link Component (for internal page links like "Back to Login")
const NavLink = ({ onClick, children }) => (
  <button
    onClick={onClick}
    className="text-indigo-600 hover:text-indigo-800 text-sm mt-5 block text-center transition duration-200 font-medium"
  >
    {children}
  </button>
);

// --- Page Components ---
// Login Page Component
const LoginPage = ({ onLogin, onNavigate }) => {
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [isLoggingIn, setIsLoggingIn] = useState(false);

  const handleSubmit = async (e) => {
    e.preventDefault();
    setIsLoggingIn(true);
    await onLogin(username, password);
    setIsLoggingIn(false);
  };

  return (
    <Card title="Login">
      <form onSubmit={handleSubmit}>
        <InputField
          id="username"
          label="Username"
          type="text"
          placeholder="Enter your username"
          value={username}
          onChange={(e) => setUsername(e.target.value)}
        />
        <InputField
          id="password"
          label="Password"
          type="password"
          placeholder="Enter your password"
          value={password}
          onChange={(e) => setPassword(e.target.value)}
        />
        <Button type="submit" disabled={isLoggingIn}>
          {isLoggingIn ? 'Logging In...' : 'Log In'}
        </Button>
      </form>
      <NavLink onClick={() => onNavigate('register')}>Don't have an account? Register</NavLink>
      <NavLink onClick={() => onNavigate('forgot-password')}>Forgot Password?</NavLink>
    </Card>
  );
};

// Register Page Component
const RegisterPage = ({ onRegister, onNavigate }) => {
  const [username, setUsername] = useState('');
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [isRegistering, setIsRegistering] = useState(false);

  const handleSubmit = async (e) => {
    e.preventDefault();
    setIsRegistering(true);
    await onRegister(username, email, password);
    setIsRegistering(false);
  };

  return (
    <Card title="Register">
      <form onSubmit={handleSubmit}>
        <InputField
          id="reg-username"
          label="Username"
          type="text"
          placeholder="Choose a username"
          value={username}
          onChange={(e) => setUsername(e.target.value)}
        />
        <InputField
          id="reg-email"
          label="Email"
          type="email"
          placeholder="Enter your email"
          value={email}
          onChange={(e) => setEmail(e.target.value)}
        />
        <InputField
          id="reg-password"
          label="Password"
          type="password"
          placeholder="Create a password"
          value={password}
          onChange={(e) => setPassword(e.target.value)}
        />
        <Button type="submit" disabled={isRegistering}>
          {isRegistering ? 'Registering...' : 'Register'}
        </Button>
      </form>
      <NavLink onClick={() => onNavigate('login')}>Already have an account? Login</NavLink>
    </Card>
  );
};

// Forgot Password Page Component
const ForgotPasswordPage = ({ onForgotPassword, onNavigate }) => {
  const [email, setEmail] = useState('');
  const [isSending, setIsSending] = useState(false);

  const handleSubmit = async (e) => {
    e.preventDefault();
    setIsSending(true);
    await onForgotPassword(email);
    setIsSending(false);
  };

  return (
    <Card title="Forgot Password">
      <form onSubmit={handleSubmit}>
        <InputField
          id="forgot-email"
          label="Email"
          type="email"
          placeholder="Enter your email"
          value={email}
          onChange={(e) => setEmail(e.target.value)}
        />
        <Button type="submit" disabled={isSending}>
          {isSending ? 'Sending Link...' : 'Reset Password'}
        </Button>
      </form>
      <NavLink onClick={() => onNavigate('login')}>Back to Login</NavLink>
    </Card>
  );
};

// Reset Password Confirmation Page Component
const ResetPasswordConfirmPage = ({ uidb64, token, onResetPassword, onNavigate }) => {
  const [newPassword, setNewPassword] = useState('');
  const [isResetting, setIsResetting] = useState(false);

  const handleSubmit = async (e) => {
    e.preventDefault();
    setIsResetting(true);
    await onResetPassword(uidb64, token, newPassword);
    setIsResetting(false);
  };

  return (
    <Card title="Set New Password">
      <form onSubmit={handleSubmit}>
        <InputField
          id="new-password"
          label="New Password"
          type="password"
          placeholder="Enter your new password"
          value={newPassword}
          onChange={(e) => setNewPassword(e.target.value)}
        />
        <Button type="submit" disabled={isResetting}>
          {isResetting ? 'Resetting...' : 'Set New Password'}
        </Button>
      </form>
      <NavLink onClick={() => onNavigate('login')}>Back to Login</NavLink>
    </Card>
  );
};

// Image Upload Page Component
const ImageUploadPage = ({ onImageUpload }) => {
  const [selectedFile, setSelectedFile] = useState(null);
  const [previewUrl, setPreviewUrl] = useState(null);
  const [isUploading, setIsUploading] = useState(false);

  const handleFileChange = (event) => {
    const file = event.target.files[0];
    if (file && file.type.startsWith('image/')) {
      setSelectedFile(file);
      setPreviewUrl(URL.createObjectURL(file));
    } else {
      setSelectedFile(null);
      setPreviewUrl(null);
      alert('Please select a valid image file (e.g., JPG, PNG, GIF).');
    }
  };

  const handleUploadClick = async () => {
    if (selectedFile) {
      setIsUploading(true);
      await onImageUpload(selectedFile);
      setIsUploading(false);
    } else {
      alert('No image selected! Please choose an image to upload.');
    }
  };

  return (
    <Card title="Upload Image for Prediction">
      <div className="mb-8">
        <label
          htmlFor="image-upload"
          className="flex flex-col items-center justify-center w-full h-56 border-2 border-dashed border-indigo-400 rounded-xl cursor-pointer bg-indigo-50 transition duration-300 ease-in-out" // No hover on background
        >
          {previewUrl ? (
            <img src={previewUrl} alt="Image Preview" className="max-h-full max-w-full object-contain rounded-xl p-2" />
          ) : (
            <div className="flex flex-col items-center justify-center pt-5 pb-6">
              <svg
                className="w-12 h-12 mb-4 text-indigo-500" // No hover on icon
                fill="none"
                stroke="currentColor"
                viewBox="0 0 24 24"
                xmlns="http://www.w3.org/2000/svg"
              >
                <path
                  strokeLinecap="round"
                  strokeLinejoin="round"
                  strokeWidth="2"
                  d="M7 16a4 4 0 01-.88-7.903A5 5 0 0115.9 6L16 6a3 3 0 013 3v10a2 2 0 01-2 2H7a2 2 0 01-2-2v-1a1 1 0 011-1h1zm4-12a1 1 0 011-1h2a1 1 0 011 1v2a1 1 0 01-1 1h-2a1 1 0 01-1-1v-2z"
                ></path>
              </svg>
              <p className="mb-2 text-lg text-gray-600"> {/* No hover on text */}
                <span className="font-bold text-indigo-600">Click to upload</span> or drag and drop
              </p>
              <p className="text-sm text-gray-500">SVG, PNG, JPG or GIF (Max 5MB)</p>
            </div>
          )}
          <input id="image-upload" type="file" className="hidden" accept="image/*" onChange={handleFileChange} />
        </label>
      </div>
      <Button onClick={handleUploadClick} disabled={isUploading}>
        {isUploading ? 'Uploading & Predicting...' : 'Upload & Predict'}
      </Button>
    </Card>
  );
};

// Prediction Result Page Component (for the most recent prediction)
const PredictionResultPage = ({ prediction, imagePreview, onNavigate }) => {
  return (
    <Card title="Current Prediction Result">
      {imagePreview && (
        <div className="mb-8 flex justify-center">
          <img src={imagePreview} alt="Uploaded for Prediction" className="max-h-80 w-auto rounded-xl shadow-lg border border-gray-200 object-contain" />
        </div>
      )}
      <div className="bg-indigo-50 p-6 rounded-lg mb-8 text-center border border-indigo-200">
        <h3 className="text-xl font-semibold text-indigo-800 mb-3">Your Image's Prediction:</h3>
        <p className="text-gray-900 font-extrabold text-3xl break-words">{prediction || 'No prediction available.'}</p>
      </div>
      <Button onClick={() => onNavigate('upload')} className="mb-4">
        Upload Another Image
      </Button>
      <NavLink onClick={() => onNavigate('history')}>View All Past Results</NavLink>
    </Card>
  );
};

// Results History Page Component (fetches and displays past predictions)

const ResultsHistoryPage = ({ authToken, API_BASE_URL }) => {
  const [history, setHistory] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  const fetchHistory = async () => {
    try {
      setLoading(true); // Set loading before fetch
      const response = await fetch(`${API_BASE_URL}/predictions/`, {
        headers: {
          'Authorization': `Token ${authToken}`,
        },
      });
      if (!response.ok) {
        // If response is not OK, try to parse error, otherwise use status text
        const errorData = await response.json().catch(() => ({})); // Try to parse JSON, fall back to empty object
        throw new Error(`HTTP error! status: ${response.status} - ${errorData.detail || response.statusText}`);
      }
      const data = await response.json();
      setHistory(data);
    } catch (err) {
      console.error('Failed to fetch prediction history:', err);
      setError(`Failed to load history: ${err.message || 'Please ensure your backend is running and you are logged in.'}`);
    } finally {
      setLoading(false);
    }
  };

  // NEW: Handle Delete Function
  const handleDelete = async (predictionId) => {
    if (window.confirm('Are you sure you want to delete this prediction? This action cannot be undone.')) {
      try {
        const response = await fetch(`${API_BASE_URL}/predictions/${predictionId}/`, {
          method: 'DELETE',
          headers: {
            'Authorization': `Token ${authToken}`,
          },
        });

        if (response.status === 204) { // 204 No Content for successful delete
          alert('Prediction deleted successfully!');
          fetchHistory(); // Refresh the list after deletion
        } else {
          const errorData = await response.json().catch(() => ({}));
          throw new Error(`Failed to delete: ${errorData.error || response.statusText}`);
        }
      } catch (err) {
        console.error('Error deleting prediction:', err);
        alert(`Error deleting prediction: ${err.message}`);
      }
    }
  };

  useEffect(() => {
    if (authToken) {
      fetchHistory();
    }
  }, [authToken, API_BASE_URL]); // Dependencies for useEffect

  return (
    <>
      {loading && <p className="text-center text-gray-600">Loading history...</p>}
      {error && <p className="text-center text-red-500">{error}</p>}
      {!loading && !error && history.length === 0 && (
        <p className="text-center text-gray-600">
          No past predictions found yet. Upload an image to start!
        </p>
      )}

      {!loading && !error && history.length > 0 && (
        <div className="w-[70%] mx-auto overflow-x-auto rounded-lg shadow-md border border-gray-100">
          <table className="w-full divide-y divide-gray-200 bg-white">
            <thead className="bg-gradient-to-r from-purple-100 to-indigo-100">
              <tr>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-700 uppercase tracking-wider">Image</th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-700 uppercase tracking-wider">File Name</th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-700 uppercase tracking-wider">Prediction</th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-700 uppercase tracking-wider">Confidence</th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-700 uppercase tracking-wider">Timestamp</th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-700 uppercase tracking-wider">Actions</th>
              </tr>
            </thead>
            <tbody className="bg-white divide-y divide-gray-200">
              {history.map((item) => (
                <tr key={item.id} className="hover:bg-gray-50 transition duration-150">
                  <td className="px-6 py-4 whitespace-nowrap">
                    {item.image_url ? (
                      <img
                        src={item.image_url}
                        alt={item.prediction_text || "Predicted"}
                        className="w-16 h-16 object-cover rounded-md shadow-sm border border-gray-100"
                      />
                    ) : (
                      <div className="w-16 h-16 bg-gray-200 rounded-md flex items-center justify-center text-gray-500 text-xs">
                        No Image
                      </div>
                    )}
                  </td>
                  <td className="px-6 py-4 whitespace-nowrap">
                    <div className="text-sm text-gray-900 truncate max-w-xs">
                      {item.image_url ? item.image_url.split("/").pop() : "N/A"}
                    </div>
                  </td>
                  <td className="px-6 py-4 whitespace-nowrap">
                    <div className="text-sm font-medium text-indigo-700">
                      {item.prediction_text || "Unknown"}
                    </div>
                  </td>
                  <td className="px-6 py-4 whitespace-nowrap">
                    <div className="text-sm text-gray-700">
                      {item.confidence !== undefined && item.confidence !== null
                        ? `${(item.confidence * 100).toFixed(2)}%`
                        : "N/A"}
                    </div>
                  </td>
                  <td className="px-6 py-4 whitespace-nowrap">
                    <div className="text-sm text-gray-500">
                      {item.timestamp ? new Date(item.timestamp).toLocaleString() : "N/A"}
                    </div>
                  </td>
                  <td className="px-6 py-4 whitespace-nowrap text-right text-sm font-medium">
                    <Button
                      onClick={() => handleDelete(item.id)}
                      className="!bg-red-500 hover:!bg-red-600 !py-1 !px-3 !text-xs !font-normal"
                    >
                      Delete
                    </Button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}


    </>


  );
};

export default App;