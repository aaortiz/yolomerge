import os
import sys
import json

def calculate_sum(numbers):
    """
    Calculate the sum of a list of numbers.
    """
    total = 0
    for num in numbers:
        total += num
    return total

class DataProcessor:
    def __init__(self, filename):
        self.filename = filename
        self.data = []
    
    def load_data(self):
        """Load data from the file."""
        with open(self.filename, 'r') as f:
            self.data = json.load(f)
        return self.data
    
    def process(self):
        """Process the loaded data."""
        if not self.data:
            self.load_data()
        
        results = []
        for item in self.data:
            results.append(item * 2)
        return results

# Main execution
if __name__ == "__main__":
    numbers = [1, 2, 3, 4, 5]
    result = calculate_sum(numbers)
    print(f"The sum is: {result}")
    
    processor = DataProcessor("data.json")
    processed = processor.process()
    print(f"Processed data: {processed}")